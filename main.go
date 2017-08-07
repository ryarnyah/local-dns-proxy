package main

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"strings"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/karlseguin/ccache"
	"github.com/miekg/dns"
	"gopkg.in/alecthomas/kingpin.v2"
	yaml "gopkg.in/yaml.v2"
)

const (
	configFilname = "config.yaml"
)

var (
	cache = ccache.New(ccache.Configure())
)

type dnsServer struct {
	DnsServer   string `yaml:"dnsServer"`
	DnsPort     int    `yaml:"dnsPort"`
	DnsProtocol string `yaml:"dnsProtocol"`
	Timeout     int    `yaml:"timeout"`
}

type authority struct {
	DnsServer   string `yaml:"dnsServer"`
	DnsPort     int    `yaml:"dnsPort"`
	DnsProtocol string `yaml:"dnsProtocol"`
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

	sync.WaitGroup
}

func (handler *dnsHandler) leadAuthority(url string) (*dnsServer, error) {
	results := []dnsServer{}

	for _, authority := range handler.config.Authorities {
		if authority.DomainName != "" && strings.HasSuffix(url, authority.DomainName) {
			results = append(results, dnsServer{
				DnsServer:   authority.DnsServer,
				DnsPort:     authority.DnsPort,
				DnsProtocol: authority.DnsProtocol,
				Timeout:     authority.Timeout,
			})
		}
	}

	log.Debugf("results %+v", results)

	if len(results) == 0 {
		for _, authority := range handler.config.Authorities {
			if authority.DomainName == "" {
				results = append(results, dnsServer{
					DnsServer:   authority.DnsServer,
					DnsPort:     authority.DnsPort,
					DnsProtocol: authority.DnsProtocol,
					Timeout:     authority.Timeout,
				})
			}
		}
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("unable to find authority for %s", url)
	}

	return &results[rand.Intn(len(results))], nil
}

func resolveDnsQuery(client *dns.Client, r *dns.Msg, cacheTTL time.Duration, server *dnsServer) (*dns.Msg, error) {
	dnsResp := r.Copy()

	for _, question := range r.Question {
		item, err := cache.Fetch("question:"+question.String(), cacheTTL, func() (interface{}, error) {
			msg := r.Copy()
			msg.Question = []dns.Question{
				question,
			}
			msg.Answer = []dns.RR{}
			log.Debugf("execute %s", question.String())

			resp, _, err := client.Exchange(msg, fmt.Sprintf("%s:%d", server.DnsServer, server.DnsPort))
			if err != nil {
				return nil, fmt.Errorf("unable to get info msg %s", err)
			}
			return resp, nil

		})
		if err != nil {
			log.Errorf("%s", err)
			dnsResp.SetRcode(dnsResp, dns.RcodeNameError)
			break
		}
		dnsResp.Answer = append(dnsResp.Answer, item.Value().(*dns.Msg).Answer...)

	}
	return dnsResp, nil
}

func (handler *dnsHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	log.Debugf("proxyRequest %+v on server %+v", r)
	handler.Add(1)
	defer handler.Done()

	questionDomain := r.Question[0].Name

	server, err := handler.leadAuthority(questionDomain)
	if err != nil {
		log.Errorf("unable to find authority for %s : %s", questionDomain, err)
		return
	}

	client := &dns.Client{
		Net:     server.DnsProtocol,
		Timeout: time.Duration(server.Timeout) * time.Second,
		UDPSize: 4096,
	}

	dnsResp, err := resolveDnsQuery(client, r, handler.config.CacheTTL, server)
	if err := w.WriteMsg(dnsResp); err != nil {
		log.Errorf("unable to write msg %s", err)
	}
}

func loadConfig() (*config, error) {
	cfg := new(config)

	data, err := ioutil.ReadFile(configFilname)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(data, cfg)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	return cfg, nil
}

func main() {
	var (
		logLevel = kingpin.Flag("log-level", "Niveau de log").Default("info").Enum("error", "warn", "debug", "panic", "info")
	)
	kingpin.Version("1.1.0")
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

	handler := &dnsHandler{
		config: cfg,
	}

	if err := dns.ListenAndServe(fmt.Sprintf("%s:%d", cfg.ServerIP, cfg.ServerPort), cfg.ServerProtocol, handler); err != nil {
		log.Fatalf("unable to serve %s", err)
	}

	handler.Wait()
}
