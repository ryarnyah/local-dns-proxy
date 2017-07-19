package main

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"strings"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/miekg/dns"
	"gopkg.in/alecthomas/kingpin.v2"
	yaml "gopkg.in/yaml.v2"
)

const (
	configFilname = "config.yaml"
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
	ServerPort     int         `yaml:"serverPort"`
	ServerIP       string      `yaml:"serverIP"`
	ServerProtocol string      `yaml:"serverProtocol"`
	Authorities    []authority `yaml:"authorities"`
}

type dnsHandler struct {
	config    *config
	tcpclient *dns.Client
	udpclient *dns.Client

	sync.WaitGroup
}

func (handler *dnsHandler) leadAuthority(url string) dnsServer {
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

	return results[rand.Intn(len(results))]
}

func (handler *dnsHandler) proxyRequest(w dns.ResponseWriter, r *dns.Msg, server dnsServer) {
	log.Debugf("proxyRequest %+v on server %+v", r, server)
	handler.Add(1)
	defer handler.Done()

	client := &dns.Client{
		Net:     server.DnsProtocol,
		Timeout: time.Duration(server.Timeout) * time.Second,
		UDPSize: 4096,
	}
	m, _, err := client.Exchange(r, fmt.Sprintf("%s:%d", server.DnsServer, server.DnsPort))

	if err != nil {
		log.Errorf("unable to get info msg %s", err)
		m = new(dns.Msg)
		m.SetRcode(r, dns.RcodeNameError)
	}
	if err := w.WriteMsg(m); err != nil {
		log.Errorf("unable to write msg %s", err)
	}
}

func (handler *dnsHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	questionDomain := r.Question[0].Name

	server := handler.leadAuthority(questionDomain)

	go handler.proxyRequest(w, r, server)
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
	kingpin.Version("1.0.0")
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
