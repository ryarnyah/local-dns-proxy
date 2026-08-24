package main

import (
	_ "embed" // needed for go:embed VERSION.txt
	"fmt"
	"hash/maphash"
	"math/rand/v2"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alecthomas/kong"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"
	yaml "gopkg.in/yaml.v3"
)

//go:embed VERSION.txt
var version string

const (
	configFilename = "config.yaml"
)

// Cache sizing defaults, overridable from config.yaml.
const (
	defaultCacheMaxEntries = 5000
	defaultCacheShards     = 64
	maxCacheShards         = 4096
)

// cacheEntry is one cached upstream answer with its expiry deadline.
type cacheEntry struct {
	msg     *dns.Msg
	expires int64 // unix nanoseconds
}

// cacheShard is an independently locked slice of the cache, so hits on
// different shards never contend.
type cacheShard struct {
	mu    sync.RWMutex
	items map[string]cacheEntry
}

// dnsCache is a sharded TTL cache for upstream answers. maphash keeps
// lookups allocation-free; shard count must be a power of two.
type dnsCache struct {
	seed   maphash.Seed
	shards []cacheShard
	mask   uint64
	limit  int // per-shard entry cap
}

// newDNSCache builds a cache from cfg; zero fields fall back to the
// defaults above.
func newDNSCache(cfg cacheConfig) *dnsCache {
	shards := cfg.Shards
	if shards == 0 {
		shards = defaultCacheShards
	}
	maxEntries := cfg.MaxEntries
	if maxEntries == 0 {
		maxEntries = defaultCacheMaxEntries
	}
	c := &dnsCache{
		seed:   maphash.MakeSeed(),
		shards: make([]cacheShard, shards),
		mask:   uint64(shards - 1),
		limit:  max(1, maxEntries/shards),
	}
	for i := range c.shards {
		c.shards[i].items = make(map[string]cacheEntry, 8)
	}
	return c
}

// shard selects the lock domain for a key; on the query hot path this
// is the only hashing step and performs no allocation.
func (c *dnsCache) shard(key string) *cacheShard {
	return &c.shards[maphash.String(c.seed, key)&c.mask]
}

// get returns the cached answer, treating expired entries as misses and
// dropping them lazily.
func (c *dnsCache) get(key string) (*dns.Msg, bool) {
	s := c.shard(key)
	now := time.Now().UnixNano()
	s.mu.RLock()
	e, ok := s.items[key]
	s.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if e.expires < now {
		s.mu.Lock()
		delete(s.items, key)
		s.mu.Unlock()
		return nil, false
	}
	return e.msg, true
}

// set stores an answer for ttl; ttl <= 0 disables caching entirely.
// At capacity it evicts expired entries first, then an arbitrary one.
func (c *dnsCache) set(key string, msg *dns.Msg, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	s := c.shard(key)
	now := time.Now().UnixNano()
	s.mu.Lock()
	if len(s.items) >= c.limit {
		for k, e := range s.items {
			if e.expires < now {
				delete(s.items, k)
			}
			if len(s.items) < c.limit {
				break
			}
		}
		for k := range s.items {
			delete(s.items, k)
			break
		}
	}
	s.items[key] = cacheEntry{msg: msg, expires: now + int64(ttl)}
	s.mu.Unlock()
}

// Shared process-wide state. cache is initialized with defaults for
// tests and direct resolveDNSQuery callers; main() swaps in the
// configured instance via configureCache before the DNS server starts
// (single-threaded, so no synchronization is required).
var (
	cache    = newDNSCache(cacheConfig{})
	inflight singleflight.Group
)

// configureCache replaces the global cache with one built from cfg.
// Must be called before serving any queries.
func configureCache(cfg cacheConfig) {
	cache = newDNSCache(cfg)
}

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

// cacheConfig tunes the answer cache; all fields optional.
type cacheConfig struct {
	TTL        time.Duration `yaml:"ttl"`
	MaxEntries int           `yaml:"maxEntries"`
	Shards     int           `yaml:"shards"`
}

// config is the on-disk configuration loaded from config.yaml.
type config struct {
	ServerPort     int           `yaml:"serverPort"`
	ServerIP       string        `yaml:"serverIP"`
	ServerProtocol string        `yaml:"serverProtocol"`
	CacheTTL       time.Duration `yaml:"cacheTTL"` // deprecated: use cache.ttl
	Cache          cacheConfig   `yaml:"cache"`
	Authorities    []authority   `yaml:"authorities"`
}

// dnsHandler implements dns.Handler: it routes each query to the right
// authority and serves answers from cache when possible.
type dnsHandler struct {
	config *config

	// authorities is the runtime view of config.Authorities with
	// canonicalized domains and pre-built clients (no per-query setup).
	authorities []resolvedAuthority

	// effectiveCacheTTL is cache.ttl, falling back to the deprecated
	// top-level cacheTTL for hand-built or legacy configurations.
	effectiveCacheTTL time.Duration

	sync.WaitGroup
}

// resolvedAuthority is an authority prepared at startup: its domain is
// canonicalized and its client pre-built so queries need no setup work.
type resolvedAuthority struct {
	server    dnsServer
	domain    string
	client    *dns.Client
	keyPrefix string
}

// newDNSHandler builds a handler from cfg, precomputing canonical domain
// names and dns.Clients for every configured authority.
func newDNSHandler(cfg *config) *dnsHandler {
	handler := &dnsHandler{config: cfg}
	handler.effectiveCacheTTL = cfg.Cache.TTL
	if handler.effectiveCacheTTL == 0 {
		handler.effectiveCacheTTL = cfg.CacheTTL
	}
	for _, authority := range cfg.Authorities {
		server := dnsServer{
			DNSServer:   authority.DNSServer,
			DNSPort:     authority.DNSPort,
			DNSProtocol: authority.DNSProtocol,
			Timeout:     authority.Timeout,
		}
		handler.authorities = append(handler.authorities, resolvedAuthority{
			server: server,
			domain: canonicalName(authority.DomainName),
			client: &dns.Client{
				Net:     authority.DNSProtocol,
				Timeout: time.Duration(authority.Timeout) * time.Second,
				UDPSize: 4096,
			},
			keyPrefix: serverKeyPrefix(&server),
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

// serverKeyPrefix builds the constant part of the cache key for one
// upstream server, so it can be precomputed once instead of per query.
func serverKeyPrefix(server *dnsServer) string {
	return "question:" + server.DNSServer + ":" + strconv.Itoa(server.DNSPort) + ":"
}

// cacheKey builds the cache key for a single question against one
// upstream server, so answers from different authorities and record
// types never collide. It performs exactly one allocation.
func cacheKey(keyPrefix string, question dns.Question) string {
	name := canonicalName(question.Name)
	var b strings.Builder
	b.Grow(len(keyPrefix) + len(name) + 16)
	b.WriteString(keyPrefix)
	b.WriteString(name)
	var scratch [20]byte
	b.Write(strconv.AppendInt(scratch[:0], int64(question.Qtype), 10))
	b.WriteByte(':')
	b.Write(strconv.AppendInt(scratch[:0], int64(question.Qclass), 10))
	return b.String()
}

// cachedFetch serves hits without any global lock; singleflight only
// serializes concurrent misses for the same key into one upstream exchange.
func cachedFetch(key string, cacheTTL time.Duration, fetch func() (*dns.Msg, error)) (*dns.Msg, error) {
	if msg, ok := cache.get(key); ok {
		return msg, nil
	}
	value, err, _ := inflight.Do(key, func() (interface{}, error) {
		if msg, ok := cache.get(key); ok {
			return msg, nil
		}
		msg, err := fetch()
		if err != nil {
			return nil, err
		}
		cache.set(key, msg, cacheTTL)
		return msg, nil
	})
	if err != nil {
		return nil, err
	}
	return value.(*dns.Msg), nil
}

// resolveDNSQuery answers every question in r by consulting the cache
// (fetching from the upstream server on miss) and merging the answers
// into a reply. Upstream failures yield a SERVFAIL reply; upstream
// rcodes such as NXDOMAIN are propagated as-is.
func resolveDNSQuery(client *dns.Client, r *dns.Msg, cacheTTL time.Duration, server *dnsServer, keyPrefix string) (*dns.Msg, error) {
	// Build the reply directly instead of copying the whole request: the
	// question section is shared read-only and answers are appended below.
	dnsResp := &dns.Msg{
		MsgHdr:   r.MsgHdr,
		Compress: true,
		Question: r.Question,
		Answer:   make([]dns.RR, 0, len(r.Question)),
	}
	dnsResp.Response = true
	// Compress responses: smaller UDP payloads mean fewer IP fragments.

	for _, question := range r.Question {
		key := cacheKey(keyPrefix, question)
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

	dnsResp, err := resolveDNSQuery(server.client, r, handler.effectiveCacheTTL, &server.server, server.keyPrefix)
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

	// Legacy top-level cacheTTL still applies when cache.ttl is unset.
	if cfg.Cache.TTL == 0 && cfg.CacheTTL != 0 {
		cfg.Cache.TTL = cfg.CacheTTL
	}
	switch {
	case cfg.Cache.Shards < 0:
		return nil, fmt.Errorf("cache.shards must be positive")
	case cfg.Cache.Shards > maxCacheShards:
		return nil, fmt.Errorf("cache.shards must not exceed %d", maxCacheShards)
	case cfg.Cache.Shards != 0 && cfg.Cache.Shards&(cfg.Cache.Shards-1) != 0:
		return nil, fmt.Errorf("cache.shards must be a power of two")
	case cfg.Cache.MaxEntries < 0:
		return nil, fmt.Errorf("cache.maxEntries must be positive")
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
	cli := struct {
		LogLevel string           `help:"Niveau de log" enum:"error,warn,debug,panic,info" default:"info"`
		Version  kong.VersionFlag `help:"Affiche la version."`
	}{}
	kong.Parse(&cli,
		kong.Name("local-dns-proxy"),
		kong.UsageOnError(),
		kong.Vars{"version": strings.TrimSpace(version)},
	)

	level, err := log.ParseLevel(cli.LogLevel)
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
	configureCache(cfg.Cache)

	if err := dns.ListenAndServe(fmt.Sprintf("%s:%d", cfg.ServerIP, cfg.ServerPort), cfg.ServerProtocol, handler); err != nil {
		log.Fatalf("unable to serve %s", err)
	}

	handler.Wait()
}
