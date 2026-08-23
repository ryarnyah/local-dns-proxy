package main

import (
	_ "embed" // needed for go:embed VERSION.txt
	"fmt"
	"math/rand/v2"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/karlseguin/ccache/v3"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"
	yaml "gopkg.in/yaml.v2"
)

//go:embed VERSION.txt
var version string

const (
	configFilename = "config.yaml"
)

var (
	cache = ccache.New[*dns.Msg](
		ccache.Configure[*dns.Msg]().
			Buckets(64).        // spread bucket-lock contention
			GetsPerPromote(64), // throttle promote-channel traffic on hot keys
	)
	inflight singleflight.Group
)

// dnsServer describes an upstream DNS server used for resolution.
type dnsServer struct {
	DNSServer   string `yaml:"dnsServer"`
	DNSPort     int    `yaml:"dnsPort"`
	DNSProtocol string `yaml:"dnsProtocol"`
	Timeout     int    `yaml:"timeout"`
}

// authority is a configured upstream DNS server, optionally scoped to a
// domain: queries matching DomainName are routed there, others fall back
// to authorities without a DomainName.
type authority struct {
	DNSServer   string `yaml:"dnsServer"`
	DNSPort     int    `yaml:"dnsPort"`
	DNSProtocol string `yaml:"dnsProtocol"`
	Timeout     int    `yaml:"timeout"`
	DomainName  string `yaml:"domainName"`
}

// config is the on-disk configuration loaded from config.yaml.
type config struct {
	ServerPort     int           `yaml:"serverPort"`
	ServerIP       string        `yaml:"serverIP"`
	ServerProtocol string        `yaml:"serverProtocol"`
	Authorities    []authority   `yaml:"authorities"`
	CacheTTL       time.Duration `yaml:"cacheTTL"`
}

// dnsHandler implements dns.Handler: it routes each query to the right
// authority and serves answers from cache when possible.
type dnsHandler struct {
	config *config

	// authorities is the runtime view of config.Authorities with
	// canonicalized domains and pre-built clients (no per-query setup).
	authorities []resolvedAuthority

	sync.WaitGroup
}

// resolvedAuthority is an authority prepared at startup: its domain is
// canonicalized and its client pre-built so queries need no setup work.
type resolvedAuthority struct {
	server dnsServer
	domain string
	client *dns.Client
}

// newDNSHandler builds a handler from cfg, precomputing canonical domain
// names and dns.Clients for every configured authority.
func newDNSHandler(cfg *config) *dnsHandler {
	handler := &dnsHandler{config: cfg}
	for _, authority := range cfg.Authorities {
		handler.authorities = append(handler.authorities, resolvedAuthority{
			server: dnsServer{
				DNSServer:   authority.DNSServer,
				DNSPort:     authority.DNSPort,
				DNSProtocol: authority.DNSProtocol,
				Timeout:     authority.Timeout,
			},
			domain: canonicalName(authority.DomainName),
			client: &dns.Client{
				Net:     authority.DNSProtocol,
				Timeout: time.Duration(authority.Timeout) * time.Second,
				UDPSize: 4096,
			},
		})
	}
	return handler
}

// canonicalName lowercases name and appends the root dot if missing,
// yielding the canonical form used for matching and cache keys.
func canonicalName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name != "" && !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}

// leadAuthority selects the upstream server for qname: domain-specific
// authorities win over defaults, and one is drawn uniformly at random
// among the matching ones for load balancing.
func (handler *dnsHandler) leadAuthority(qname string) (*resolvedAuthority, error) {
	qname = canonicalName(qname)

	// Prefer domain-specific authorities, then fall back to defaults.
	// Randomly pick among all matches.
	if a := handler.pickAuthority(qname, true); a != nil {
		return a, nil
	}
	if a := handler.pickAuthority(qname, false); a != nil {
		return a, nil
	}

	return nil, fmt.Errorf("unable to find authority for %s", qname)
}

// pickAuthority returns one authority among those matching qname, or
// nil when none does. When specific is true only domain-scoped
// authorities are considered; when false only the default ones.
func (handler *dnsHandler) pickAuthority(qname string, specific bool) *resolvedAuthority {
	candidates := make([]*resolvedAuthority, 0, len(handler.authorities))
	for i := range handler.authorities {
		if handler.authorities[i].matchesDomain(qname, specific) {
			candidates = append(candidates, &handler.authorities[i])
		}
	}
	switch len(candidates) {
	case 0:
		return nil
	case 1:
		return candidates[0]
	default:
		return candidates[rand.IntN(len(candidates))]
	}
}

// subDomainOf reports whether qname equals parent or is a child of it.
// Both names must be canonical (lowercase, root-terminated). Unlike
// dns.IsSubDomain this performs no allocations.
func subDomainOf(parent, qname string) bool {
	i := len(qname) - len(parent)
	if i < 0 || qname[i:] != parent {
		return false
	}
	return i == 0 || qname[i-1] == '.'
}

// matchesDomain reports whether a considers itself responsible for
// qname: scoped authorities match their subtree, default authorities
// match everything.
func (a *resolvedAuthority) matchesDomain(qname string, specific bool) bool {
	if specific {
		return a.domain != "" && subDomainOf(a.domain, qname)
	}
	return a.domain == ""
}

// cacheKey builds the cache key for a single question against one
// upstream server, so answers from different authorities and record
// types never collide.
func cacheKey(server *dnsServer, question dns.Question) string {
	var b strings.Builder
	b.Grow(len(server.DNSServer) + len(question.Name) + 24)
	b.WriteString("question:")
	b.WriteString(server.DNSServer)
	b.WriteByte(':')
	b.WriteString(strconv.Itoa(server.DNSPort))
	b.WriteByte(':')
	b.WriteString(canonicalName(question.Name))
	b.WriteByte(':')
	b.WriteString(strconv.Itoa(int(question.Qtype)))
	b.WriteByte(':')
	b.WriteString(strconv.Itoa(int(question.Qclass)))
	return b.String()
}

// cachedFetch serves hits without any global lock; singleflight only
// serializes concurrent misses for the same key into one upstream exchange.
func cachedFetch(key string, cacheTTL time.Duration, fetch func() (*dns.Msg, error)) (*dns.Msg, error) {
	if item := cache.Get(key); item != nil && !item.Expired() {
		return item.Value(), nil
	}
	value, err, _ := inflight.Do(key, func() (interface{}, error) {
		item, err := cache.Fetch(key, cacheTTL, fetch)
		if err != nil {
			return nil, err
		}
		return item.Value(), nil
	})
	if err != nil {
		return nil, err
	}
	return value.(*dns.Msg), nil
}

// resolveDNSQuery answers every question in r by consulting the cache
// (fetching from server on miss) and merging the answers into a reply.
// Upstream failures yield a SERVFAIL reply; upstream rcodes such as
// NXDOMAIN are propagated as-is.
func resolveDNSQuery(client *dns.Client, r *dns.Msg, cacheTTL time.Duration, server *dnsServer) (*dns.Msg, error) {
	// Build the reply directly instead of copying the whole request: the
	// question section is shared read-only and answers are appended below.
	dnsResp := &dns.Msg{
		MsgHdr:   r.MsgHdr,
		Compress: true,
		Question: r.Question,
		Answer:   []dns.RR{},
	}
	dnsResp.Response = true
	// Compress responses: smaller UDP payloads mean fewer IP fragments.

	for _, question := range r.Question {
		key := cacheKey(server, question)
		upstream, err := cachedFetch(key, cacheTTL, func() (*dns.Msg, error) {
			msg := r.Copy()
			msg.Question = []dns.Question{
				question,
			}
			msg.Answer = []dns.RR{}
			log.Debugf("execute %s", question.String())

			resp, _, err := client.Exchange(msg, fmt.Sprintf("%s:%d", server.DNSServer, server.DNSPort))
			if err != nil {
				return nil, fmt.Errorf("unable to get info msg %s", err)
			}
			return resp, nil
		})
		if err != nil {
			log.Errorf("%s", err)
			dnsResp.Rcode = dns.RcodeServerFailure
			dnsResp.Answer = nil
			break
		}
		dnsResp.Rcode = upstream.Rcode
		dnsResp.RecursionAvailable = upstream.RecursionAvailable
		dnsResp.Answer = append(dnsResp.Answer, upstream.Answer...)

	}
	return dnsResp, nil
}

// ServeDNS implements dns.Handler. It answers FORMERR for malformed
// queries without questions, REFUSED when no authority matches, and
// otherwise proxies the query to the selected authority.
func (handler *dnsHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	log.Debugf("proxyRequest %+v on server", r)
	handler.Add(1)
	defer handler.Done()

	if len(r.Question) == 0 {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeFormatError)
		if err := w.WriteMsg(m); err != nil {
			log.Errorf("unable to write msg %s", err)
		}
		return
	}

	questionDomain := r.Question[0].Name

	server, err := handler.leadAuthority(questionDomain)
	if err != nil {
		log.Errorf("unable to find authority for %s : %s", questionDomain, err)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		if err := w.WriteMsg(m); err != nil {
			log.Errorf("unable to write msg %s", err)
		}
		return
	}

	dnsResp, err := resolveDNSQuery(server.client, r, handler.config.CacheTTL, &server.server)
	if err != nil {
		log.Errorf("unable to find resolve dns query for %s : %s", questionDomain, err)
		return
	}
	if err := w.WriteMsg(dnsResp); err != nil {
		log.Errorf("unable to write msg %s", err)
	}
}

// loadConfig reads and validates config.yaml from the working
// directory, rejecting malformed or unsafe values at startup.
func loadConfig() (*config, error) {
	cfg := new(config)

	data, err := os.ReadFile(configFilename)
	if err != nil {
		return nil, err
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("unable to parse config: %w", err)
	}

	if len(cfg.Authorities) == 0 {
		return nil, fmt.Errorf("no authorities configured")
	}

	if cfg.ServerPort < 1 || cfg.ServerPort > 65535 {
		return nil, fmt.Errorf("invalid serverPort %d", cfg.ServerPort)
	}
	if cfg.ServerProtocol != "udp" && cfg.ServerProtocol != "tcp" {
		return nil, fmt.Errorf("invalid serverProtocol %q", cfg.ServerProtocol)
	}

	for i, authority := range cfg.Authorities {
		if authority.DNSServer == "" {
			return nil, fmt.Errorf("authority %d: dnsServer is required", i)
		}
		if authority.DNSPort < 1 || authority.DNSPort > 65535 {
			return nil, fmt.Errorf("authority %d (%s): invalid dnsPort %d", i, authority.DNSServer, authority.DNSPort)
		}
		if authority.DNSProtocol != "udp" && authority.DNSProtocol != "tcp" {
			return nil, fmt.Errorf("authority %d (%s): invalid dnsProtocol %q", i, authority.DNSServer, authority.DNSProtocol)
		}
		if authority.Timeout <= 0 {
			return nil, fmt.Errorf("authority %d (%s): timeout must be greater than 0", i, authority.DNSServer)
		}
	}

	return cfg, nil
}

// main parses flags, loads the configuration and serves DNS until a
// fatal error occurs.
func main() {
	var (
		logLevel = kingpin.Flag("log-level", "Niveau de log").Default("info").Enum("error", "warn", "debug", "panic", "info")
	)
	kingpin.Version(strings.TrimSpace(version))
	kingpin.Parse()

	level, err := log.ParseLevel(*logLevel)
	if err != nil {
		log.Panicf("unable to parse log level %s", err)
	}
	log.SetLevel(level)

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("unable to load config %s", err)
	}

	log.Debugf("cfg %+v", cfg)

	handler := newDNSHandler(cfg)

	if err := dns.ListenAndServe(fmt.Sprintf("%s:%d", cfg.ServerIP, cfg.ServerPort), cfg.ServerProtocol, handler); err != nil {
		log.Fatalf("unable to serve %s", err)
	}

	handler.Wait()
}
