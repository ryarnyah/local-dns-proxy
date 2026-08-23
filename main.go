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
	"github.com/karlseguin/ccache"
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
	cache = ccache.New(
		ccache.Configure().
			Buckets(64).        // spread bucket-lock contention
			GetsPerPromote(64), // throttle promote-channel traffic on hot keys
	)
	inflight singleflight.Group
)

type dnsServer struct {
	DNSServer   string `yaml:"dnsServer"`
	DNSPort     int    `yaml:"dnsPort"`
	DNSProtocol string `yaml:"dnsProtocol"`
	Timeout     int    `yaml:"timeout"`
}

type authority struct {
	DNSServer   string `yaml:"dnsServer"`
	DNSPort     int    `yaml:"dnsPort"`
	DNSProtocol string `yaml:"dnsProtocol"`
	Timeout     int    `yaml:"timeout"`
	DomainName  string `yaml:"domainName"`
}

type config struct {
	ServerPort     int           `yaml:"serverPort"`
	ServerIP       string        `yaml:"serverIP"`
	ServerProtocol string        `yaml:"serverProtocol"`
	Authorities    []authority   `yaml:"authorities"`
	CacheTTL       time.Duration `yaml:"cacheTTL"`
}

type dnsHandler struct {
	config *config

	// authorities is the runtime view of config.Authorities with
	// canonicalized domains and pre-built clients (no per-query setup).
	authorities []resolvedAuthority

	sync.WaitGroup
}

type resolvedAuthority struct {
	server dnsServer
	domain string
	client *dns.Client
}

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

func canonicalName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name != "" && !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}

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

func (a *resolvedAuthority) matchesDomain(qname string, specific bool) bool {
	if specific {
		return a.domain != "" && subDomainOf(a.domain, qname)
	}
	return a.domain == ""
}

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
func cachedFetch(key string, cacheTTL time.Duration, fetch func() (interface{}, error)) (interface{}, error) {
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
	return value, err
}

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
		value, err := cachedFetch(key, cacheTTL, func() (interface{}, error) {
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
		upstream := value.(*dns.Msg)
		dnsResp.Rcode = upstream.Rcode
		dnsResp.RecursionAvailable = upstream.RecursionAvailable
		dnsResp.Answer = append(dnsResp.Answer, upstream.Answer...)

	}
	return dnsResp, nil
}

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
