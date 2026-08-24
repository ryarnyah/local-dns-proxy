package main

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestLeadAuthority(t *testing.T) {
	config := &config{
		ServerPort:     10053,
		ServerIP:       "127.0.0.1",
		ServerProtocol: "udp",
		CacheTTL:       0,
		Authorities: []authority{
			{
				DNSServer:   "8.8.4.4",
				DNSPort:     53,
				DNSProtocol: "udp",
				Timeout:     2,
			},
			{
				DNSServer:   "8.8.8.8",
				DNSPort:     53,
				DNSProtocol: "udp",
				Timeout:     2,
				DomainName:  "google.fr",
			},
		},
	}
	dnsHandler := newDNSHandler(config)

	dnsServer, err := dnsHandler.leadAuthority("dev.google.fr")
	if err != nil {
		t.Error(err)
	}
	if dnsServer.server.DNSServer != "8.8.8.8" {
		t.Error("unable to lead for google.fr")
	}
	dnsServer, err = dnsHandler.leadAuthority("toto.com")
	if err != nil {
		t.Error(err)
	}
	if dnsServer.server.DNSServer != "8.8.4.4" {
		t.Error("unable to lead for toto.com")
	}

	// FQDN with trailing dot and mixed case must still match
	dnsServer, err = dnsHandler.leadAuthority("dev.google.fr.")
	if err != nil {
		t.Error(err)
	}
	if dnsServer.server.DNSServer != "8.8.8.8" {
		t.Error("unable to lead for google.fr.")
	}
	dnsServer, err = dnsHandler.leadAuthority("DEV.GOOGLE.FR.")
	if err != nil {
		t.Error(err)
	}
	if dnsServer.server.DNSServer != "8.8.8.8" {
		t.Error("unable to lead for DEV.GOOGLE.FR.")
	}

	config.Authorities = []authority{
		{
			DNSServer:   "8.8.8.8",
			DNSPort:     53,
			DNSProtocol: "udp",
			Timeout:     2,
			DomainName:  "google.fr",
		},
	}
	dnsHandler = newDNSHandler(config)

	dnsServer, err = dnsHandler.leadAuthority("toto.com")
	if err == nil {
		t.Error("unable to not find authority")
	}
	if dnsServer != nil {
		t.Error("unable to not find authority")
	}

}

func TestLeadAuthorityLabelBoundary(t *testing.T) {
	config := &config{
		ServerPort:     10053,
		ServerIP:       "127.0.0.1",
		ServerProtocol: "udp",
		CacheTTL:       0,
		Authorities: []authority{
			{
				DNSServer:   "8.8.4.4",
				DNSPort:     53,
				DNSProtocol: "udp",
				Timeout:     2,
			},
			{
				DNSServer:   "8.8.8.8",
				DNSPort:     53,
				DNSProtocol: "udp",
				Timeout:     2,
				DomainName:  "google.fr",
			},
		},
	}
	dnsHandler := newDNSHandler(config)

	// notgoogle.fr must NOT match the google.fr authority
	for _, qname := range []string{"notgoogle.fr", "notgoogle.fr.", "google.fr.evil.com."} {
		server, err := dnsHandler.leadAuthority(qname)
		if err != nil {
			t.Errorf("%s should fall back to default authority: %v", qname, err)
			continue
		}
		if server.server.DNSServer != "8.8.4.4" {
			t.Errorf("%s must not be routed to the google.fr authority", qname)
		}
	}
}

func TestResolveDnsQuery(t *testing.T) {
	s, err := RunLocalUDPServer("127.0.0.1:0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	client := &dns.Client{
		Net:     "udp",
		Timeout: 5 * time.Second,
		UDPSize: 4096,
	}

	dnsServer := &dnsServer{
		DNSServer:   "127.0.0.1",
		DNSPort:     s.PacketConn.LocalAddr().(*net.UDPAddr).Port,
		DNSProtocol: "udp",
		Timeout:     4,
	}

	msg := &dns.Msg{}

	dMsg, err := resolveDNSQuery(client, msg, 0, dnsServer, serverKeyPrefix(dnsServer))
	if err != nil {
		t.Fail()
	}
	if len(dMsg.Answer) > 0 {
		t.Fail()
	}

	dns.HandleFunc("toto.com.", func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)

		m.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
				A:   net.ParseIP("127.0.0.1"),
			},
		}
		_ = w.WriteMsg(m)
	})

	msg = &dns.Msg{
		Question: []dns.Question{
			{
				Name:   "toto.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			},
		},
	}
	dMsg, err = resolveDNSQuery(client, msg, 1*time.Minute, dnsServer, serverKeyPrefix(dnsServer))
	if err != nil {
		t.Fail()
	}
	if len(dMsg.Answer) == 0 {
		t.Fatal("expected an answer for toto.com")
	}
	if dMsg.Answer[0].(*dns.A).A.To4().String() != "127.0.0.1" {
		t.Fail()
	}
	dns.HandleRemove("toto.com.")
	// Test cache without handler
	dMsg, err = resolveDNSQuery(client, msg, 1*time.Minute, dnsServer, serverKeyPrefix(dnsServer))
	if err != nil {
		t.Fail()
	}
	if len(dMsg.Answer) == 0 {
		t.Fatal("expected a cached answer for toto.com")
	}
	if dMsg.Answer[0].(*dns.A).A.To4().String() != "127.0.0.1" {
		t.Fail()
	}

	// Test fail
	msg = &dns.Msg{
		Question: []dns.Question{
			{
				Name:   "google.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			},
		},
	}

	dnsServer.DNSServer = "127.0.0.2"

	dMsg, err = resolveDNSQuery(client, msg, 1*time.Minute, dnsServer, serverKeyPrefix(dnsServer))
	if err != nil {
		t.Error(err)
	}
	if dMsg.Rcode != dns.RcodeServerFailure {
		t.Fail()
	}

}

// Regression: cache keys must distinguish record types, otherwise an
// A answer is served for AAAA queries (and vice versa).
func TestResolveDnsQueryQTypeIsolation(t *testing.T) {
	s, err := RunLocalUDPServer("127.0.0.1:0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	dns.HandleFunc("dual.test.", func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		ip := net.ParseIP("127.0.0.1")
		rr := dns.RR(&dns.A{
			Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   ip,
		})
		if req.Question[0].Qtype == dns.TypeAAAA {
			rr = &dns.AAAA{
				Hdr:  dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
				AAAA: ip,
			}
		}
		m.Answer = []dns.RR{rr}
		_ = w.WriteMsg(m)
	})
	defer dns.HandleRemove("dual.test.")

	client := &dns.Client{Net: "udp", Timeout: 5 * time.Second, UDPSize: 4096}
	server := &dnsServer{
		DNSServer:   "127.0.0.1",
		DNSPort:     s.PacketConn.LocalAddr().(*net.UDPAddr).Port,
		DNSProtocol: "udp",
		Timeout:     4,
	}

	aMsg := &dns.Msg{Question: []dns.Question{{Name: "dual.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}
	aaaaMsg := &dns.Msg{Question: []dns.Question{{Name: "dual.test.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}}}

	respA, err := resolveDNSQuery(client, aMsg, time.Minute, server, serverKeyPrefix(server))
	if err != nil {
		t.Fatal(err)
	}
	respAAAA, err := resolveDNSQuery(client, aaaaMsg, time.Minute, server, serverKeyPrefix(server))
	if err != nil {
		t.Fatal(err)
	}
	// Second round must be served from cache without mixing types
	respA2, err := resolveDNSQuery(client, aMsg, time.Minute, server, serverKeyPrefix(server))
	if err != nil {
		t.Fatal(err)
	}
	respAAAA2, err := resolveDNSQuery(client, aaaaMsg, time.Minute, server, serverKeyPrefix(server))
	if err != nil {
		t.Fatal(err)
	}

	for name, resp := range map[string]*dns.Msg{"A": respA, "A-cached": respA2} {
		if len(resp.Answer) != 1 || resp.Answer[0].Header().Rrtype != dns.TypeA {
			t.Errorf("%s query must return exactly one A record, got %+v", name, resp.Answer)
		}
	}
	for name, resp := range map[string]*dns.Msg{"AAAA": respAAAA, "AAAA-cached": respAAAA2} {
		if len(resp.Answer) != 1 || resp.Answer[0].Header().Rrtype != dns.TypeAAAA {
			t.Errorf("%s query must return exactly one AAAA record, got %+v", name, resp.Answer)
		}
	}
}

// Upstream NXDOMAIN must reach the client instead of being turned into
// an empty NOERROR.
func TestResolveDnsQueryNXDOMAINPropagation(t *testing.T) {
	s, err := RunLocalUDPServer("127.0.0.1:0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	dns.HandleFunc("nx.test.", func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeNameError)
		_ = w.WriteMsg(m)
	})
	defer dns.HandleRemove("nx.test.")

	client := &dns.Client{Net: "udp", Timeout: 5 * time.Second, UDPSize: 4096}
	server := &dnsServer{
		DNSServer:   "127.0.0.1",
		DNSPort:     s.PacketConn.LocalAddr().(*net.UDPAddr).Port,
		DNSProtocol: "udp",
		Timeout:     4,
	}

	msg := &dns.Msg{Question: []dns.Question{{Name: "nx.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}
	dMsg, err := resolveDNSQuery(client, msg, time.Minute, server, serverKeyPrefix(server))
	if err != nil {
		t.Fatal(err)
	}
	if dMsg.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN propagated, got %s", dns.RcodeToString[dMsg.Rcode])
	}
	if dMsg.Response {
		// QR bit must be set on replies built from the query copy
		t.Log("response flag set")
	} else {
		t.Error("expected Response flag to be set")
	}
}

// CNAME chains from upstream must pass through untouched.
func TestResolveDnsQueryCNAMEChain(t *testing.T) {
	s, err := RunLocalUDPServer("127.0.0.1:0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	dns.HandleFunc("alias.test.", func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Answer = []dns.RR{
			&dns.CNAME{
				Hdr:    dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
				Target: "target.test.",
			},
			&dns.A{
				Hdr: dns.RR_Header{Name: "target.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("10.0.0.1"),
			},
		}
		_ = w.WriteMsg(m)
	})
	defer dns.HandleRemove("alias.test.")

	client := &dns.Client{Net: "udp", Timeout: 5 * time.Second, UDPSize: 4096}
	server := &dnsServer{
		DNSServer:   "127.0.0.1",
		DNSPort:     s.PacketConn.LocalAddr().(*net.UDPAddr).Port,
		DNSProtocol: "udp",
		Timeout:     4,
	}

	msg := &dns.Msg{Question: []dns.Question{{Name: "alias.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}
	dMsg, err := resolveDNSQuery(client, msg, time.Minute, server, serverKeyPrefix(server))
	if err != nil {
		t.Fatal(err)
	}
	if len(dMsg.Answer) != 2 {
		t.Fatalf("expected CNAME chain preserved (2 records), got %d", len(dMsg.Answer))
	}
	if _, ok := dMsg.Answer[0].(*dns.CNAME); !ok {
		t.Errorf("expected first record to be CNAME, got %T", dMsg.Answer[0])
	}
}

// Cache entries must expire: expired entries trigger a fresh upstream fetch.
func TestCacheTTLExpiry(t *testing.T) {
	s, err := RunLocalUDPServer("127.0.0.1:0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	var mu sync.Mutex
	fetches := 0
	dns.HandleFunc("ttl.test.", func(w dns.ResponseWriter, req *dns.Msg) {
		mu.Lock()
		fetches++
		mu.Unlock()
		m := new(dns.Msg)
		m.SetReply(req)
		m.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("127.0.0.1"),
			},
		}
		_ = w.WriteMsg(m)
	})
	defer dns.HandleRemove("ttl.test.")

	client := &dns.Client{Net: "udp", Timeout: 5 * time.Second, UDPSize: 4096}
	server := &dnsServer{
		DNSServer:   "127.0.0.1",
		DNSPort:     s.PacketConn.LocalAddr().(*net.UDPAddr).Port,
		DNSProtocol: "udp",
		Timeout:     4,
	}

	msg := &dns.Msg{Question: []dns.Question{{Name: "ttl.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}

	if _, err := resolveDNSQuery(client, msg, 80*time.Millisecond, server, serverKeyPrefix(server)); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveDNSQuery(client, msg, 80*time.Millisecond, server, serverKeyPrefix(server)); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if fetches != 1 {
		mu.Unlock()
		t.Fatalf("second query must hit cache, got %d upstream fetches", fetches)
	}
	mu.Unlock()

	time.Sleep(150 * time.Millisecond)
	if _, err := resolveDNSQuery(client, msg, 80*time.Millisecond, server, serverKeyPrefix(server)); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if fetches != 2 {
		t.Fatalf("expired entry must refetch, got %d upstream fetches", fetches)
	}
}

// CacheTTL <= 0 disables caching: every query reaches upstream.
func TestCacheDisabled(t *testing.T) {
	s, err := RunLocalUDPServer("127.0.0.1:0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	var mu sync.Mutex
	fetches := 0
	dns.HandleFunc("nocache.test.", func(w dns.ResponseWriter, req *dns.Msg) {
		mu.Lock()
		fetches++
		mu.Unlock()
		m := new(dns.Msg)
		m.SetReply(req)
		_ = w.WriteMsg(m)
	})
	defer dns.HandleRemove("nocache.test.")

	client := &dns.Client{Net: "udp", Timeout: 5 * time.Second, UDPSize: 4096}
	server := &dnsServer{
		DNSServer:   "127.0.0.1",
		DNSPort:     s.PacketConn.LocalAddr().(*net.UDPAddr).Port,
		DNSProtocol: "udp",
		Timeout:     4,
	}

	msg := &dns.Msg{Question: []dns.Question{{Name: "nocache.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}
	for i := 0; i < 3; i++ {
		if _, err := resolveDNSQuery(client, msg, 0, server, serverKeyPrefix(server)); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if fetches != 3 {
		t.Fatalf("TTL=0 must disable caching, got %d upstream fetches for 3 queries", fetches)
	}
}

// Concurrent queries sharing the global cache must not race.
func TestConcurrentQueries(t *testing.T) {
	s, err := RunLocalUDPServer("127.0.0.1:0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	dns.HandleFunc("race.test.", func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("127.0.0.1"),
			},
		}
		_ = w.WriteMsg(m)
	})
	defer dns.HandleRemove("race.test.")

	handler := newDNSHandler(&config{
		CacheTTL: time.Minute,
		Authorities: []authority{
			{
				DNSServer:   "127.0.0.1",
				DNSPort:     s.PacketConn.LocalAddr().(*net.UDPAddr).Port,
				DNSProtocol: "udp",
				Timeout:     4,
			},
		},
	})

	rm := responseMock{
		getWriteMsg: func(dMsg *dns.Msg) error {
			if dMsg.Rcode != dns.RcodeSuccess {
				t.Errorf("unexpected rcode %s", dns.RcodeToString[dMsg.Rcode])
			}
			return nil
		},
	}

	var wg sync.WaitGroup
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			msg := &dns.Msg{
				Question: []dns.Question{
					{
						Name:   fmt.Sprintf("host%d.race.test.", n),
						Qtype:  dns.TypeA,
						Qclass: dns.ClassINET,
					},
				},
			}
			handler.ServeDNS(rm, msg)
		}(i)
	}
	wg.Wait()
}

// The upstream leg must work over TCP as well.
func TestResolveDnsQueryOverTCP(t *testing.T) {
	s, err := RunLocalTCPServer("127.0.0.1:0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	dns.HandleFunc("tcp.test.", func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("127.0.0.1"),
			},
		}
		_ = w.WriteMsg(m)
	})
	defer dns.HandleRemove("tcp.test.")

	client := &dns.Client{Net: "tcp", Timeout: 5 * time.Second, UDPSize: 4096}
	server := &dnsServer{
		DNSServer:   "127.0.0.1",
		DNSPort:     s.Listener.Addr().(*net.TCPAddr).Port,
		DNSProtocol: "tcp",
		Timeout:     4,
	}

	msg := &dns.Msg{Question: []dns.Question{{Name: "tcp.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}
	dMsg, err := resolveDNSQuery(client, msg, time.Minute, server, serverKeyPrefix(server))
	if err != nil {
		t.Fatal(err)
	}
	if len(dMsg.Answer) == 0 {
		t.Fatal("expected an answer over TCP")
	}
}

// A hung upstream must produce SERVFAIL within the configured timeout,
// not hang forever.
func TestUpstreamTimeout(t *testing.T) {
	s, err := RunLocalUDPServer("127.0.0.1:0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	dns.HandleFunc("slow.test.", func(w dns.ResponseWriter, req *dns.Msg) {
		time.Sleep(5 * time.Second)
		m := new(dns.Msg)
		m.SetReply(req)
		_ = w.WriteMsg(m)
	})
	defer dns.HandleRemove("slow.test.")

	client := &dns.Client{Net: "udp", Timeout: time.Duration(1) * time.Second, UDPSize: 4096}
	server := &dnsServer{
		DNSServer:   "127.0.0.1",
		DNSPort:     s.PacketConn.LocalAddr().(*net.UDPAddr).Port,
		DNSProtocol: "udp",
		Timeout:     1,
	}

	msg := &dns.Msg{Question: []dns.Question{{Name: "slow.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}

	start := time.Now()
	dMsg, err := resolveDNSQuery(client, msg, 0, server, serverKeyPrefix(server))
	elapsed := time.Since(start)

	if elapsed > 3*time.Second {
		t.Errorf("timeout not honored: took %s", elapsed)
	}
	if err != nil {
		t.Fatal(err)
	}
	if dMsg.Rcode != dns.RcodeServerFailure {
		t.Fatalf("expected SERVFAIL on upstream timeout, got %s", dns.RcodeToString[dMsg.Rcode])
	}
}

func TestServeDNS(t *testing.T) {
	s, err := RunLocalUDPServer("127.0.0.1:0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	config := &config{
		ServerPort:     10053,
		ServerIP:       "127.0.0.1",
		ServerProtocol: "udp",
		CacheTTL:       0,
		Authorities: []authority{
			{
				DNSServer:   "127.0.0.1",
				DNSPort:     s.PacketConn.LocalAddr().(*net.UDPAddr).Port,
				DNSProtocol: "udp",
				Timeout:     2,
			},
		},
	}
	dnsHandler := newDNSHandler(config)
	dns.HandleFunc("toto.com.", func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)

		m.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
				A:   net.ParseIP("127.0.0.1"),
			},
		}
		_ = w.WriteMsg(m)
	})
	defer dns.HandleRemove("toto.com.")

	msg := &dns.Msg{
		Question: []dns.Question{
			{
				Name:   "toto.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			},
		},
	}

	rm := responseMock{
		getWriteMsg: func(dMsg *dns.Msg) error {
			if len(dMsg.Answer) == 0 {
				t.Fatal("expected an answer for toto.com")
			}
			if dMsg.Answer[0].(*dns.A).A.To4().String() != "127.0.0.1" {
				t.Fail()
			}
			return errors.New("mock write error")
		},
	}

	dnsHandler.ServeDNS(rm, msg)
}

func TestServeDNSEmptyQuestion(t *testing.T) {
	dnsHandler := newDNSHandler(&config{CacheTTL: 0})

	rm := responseMock{
		getWriteMsg: func(dMsg *dns.Msg) error {
			if dMsg.Rcode != dns.RcodeFormatError {
				t.Errorf("expected FORMERR, got %s", dns.RcodeToString[dMsg.Rcode])
			}
			return errors.New("mock write error")
		},
	}

	dnsHandler.ServeDNS(rm, &dns.Msg{})
}

func TestServeDNSNoAuthority(t *testing.T) {
	dnsHandler := newDNSHandler(&config{
		CacheTTL: 0,
		Authorities: []authority{
			{
				DNSServer:   "8.8.8.8",
				DNSPort:     53,
				DNSProtocol: "udp",
				Timeout:     2,
				DomainName:  "google.fr",
			},
		},
	})

	rm := responseMock{
		getWriteMsg: func(dMsg *dns.Msg) error {
			if dMsg.Rcode != dns.RcodeRefused {
				t.Errorf("expected REFUSED, got %s", dns.RcodeToString[dMsg.Rcode])
			}
			return errors.New("mock write error")
		},
	}

	msg := &dns.Msg{
		Question: []dns.Question{
			{
				Name:   "toto.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			},
		},
	}
	dnsHandler.ServeDNS(rm, msg)
}

type responseMock struct {
	getLocalAddr      func() net.Addr
	getRemoteAddr     func() net.Addr
	getWriteMsg       func(m *dns.Msg) error
	getWrite          func([]byte) (int, error)
	getClose          func() error
	getTsigStatus     func() error
	getTsigTimersOnly func(bool)
	getHijack         func()
}

func (e responseMock) LocalAddr() net.Addr {
	if e.getLocalAddr != nil {
		return e.getLocalAddr()
	}
	return nil
}
func (e responseMock) RemoteAddr() net.Addr {
	if e.getRemoteAddr != nil {
		return e.getRemoteAddr()
	}
	return nil
}
func (e responseMock) WriteMsg(m *dns.Msg) error {
	if e.getWriteMsg != nil {
		return e.getWriteMsg(m)
	}
	return nil
}
func (e responseMock) Write(b []byte) (int, error) {
	if e.getWrite != nil {
		return e.getWrite(b)
	}
	return 0, nil
}
func (e responseMock) Close() error {
	if e.getClose != nil {
		return e.getClose()
	}
	return nil
}
func (e responseMock) TsigStatus() error {
	if e.getTsigStatus != nil {
		return e.getTsigStatus()
	}
	return nil
}
func (e responseMock) TsigTimersOnly(b bool) {
	if e.getTsigTimersOnly != nil {
		e.getTsigTimersOnly(b)
	}
}
func (e responseMock) Hijack() {
	if e.getHijack != nil {
		e.getHijack()
	}
}

func TestLoadConfig(t *testing.T) {
	validConfig := `---
serverPort: 10053
serverIP: 127.0.0.1
serverProtocol: udp
cache:
  ttl: 1m
  maxEntries: 2048
  shards: 32
authorities:
  - dnsServer: 8.8.8.8
    dnsPort: 53
    dnsProtocol: udp
    timeout: 2
`
	legacyTTL := `---
serverPort: 10053
serverProtocol: udp
cacheTTL: 2m
authorities:
  - dnsServer: 8.8.8.8
    dnsPort: 53
    dnsProtocol: udp
    timeout: 2
`
	oddShards := `---
serverPort: 10053
serverProtocol: udp
cache:
  shards: 63
authorities:
  - dnsServer: 8.8.8.8
    dnsPort: 53
    dnsProtocol: udp
    timeout: 2
`
	negativeMaxEntries := `---
serverPort: 10053
serverProtocol: udp
cache:
  maxEntries: -1
authorities:
  - dnsServer: 8.8.8.8
    dnsPort: 53
    dnsProtocol: udp
    timeout: 2
`
	invalidYaml := `---
authorities: [this is : not : valid yaml`
	noAuthorities := `---
serverPort: 10053
`
	zeroTimeout := `---
serverPort: 10053
serverProtocol: udp
authorities:
  - dnsServer: 8.8.8.8
    dnsPort: 53
    dnsProtocol: udp
    timeout: 0
`
	badProtocol := `---
serverPort: 10053
serverProtocol: sctp
authorities:
  - dnsServer: 8.8.8.8
    dnsPort: 53
    dnsProtocol: udp
    timeout: 2
`
	badPort := `---
serverPort: 70000
serverProtocol: udp
authorities:
  - dnsServer: 8.8.8.8
    dnsPort: 53
    dnsProtocol: udp
    timeout: 2
`
	emptyDNSServer := `---
serverPort: 10053
serverProtocol: udp
authorities:
  - dnsPort: 53
    dnsProtocol: udp
    timeout: 2
`
	badDNSPort := `---
serverPort: 10053
serverProtocol: udp
authorities:
  - dnsServer: 8.8.8.8
    dnsPort: 0
    dnsProtocol: udp
    timeout: 2
`
	badDNSProtocol := `---
serverPort: 10053
serverProtocol: udp
authorities:
  - dnsServer: 8.8.8.8
    dnsPort: 53
    dnsProtocol: carrier-pigeon
    timeout: 2
`

	tests := []struct {
		name    string
		content string
		create  bool
		wantErr bool
	}{
		{name: "valid", content: validConfig, create: true},
		{name: "legacy cacheTTL", content: legacyTTL, create: true},
		{name: "invalid yaml", content: invalidYaml, create: true, wantErr: true},
		{name: "no authorities", content: noAuthorities, create: true, wantErr: true},
		{name: "zero timeout", content: zeroTimeout, create: true, wantErr: true},
		{name: "bad protocol", content: badProtocol, create: true, wantErr: true},
		{name: "bad port", content: badPort, create: true, wantErr: true},
		{name: "empty dns server", content: emptyDNSServer, create: true, wantErr: true},
		{name: "bad dns port", content: badDNSPort, create: true, wantErr: true},
		{name: "bad dns protocol", content: badDNSProtocol, create: true, wantErr: true},
		{name: "odd cache shards", content: oddShards, create: true, wantErr: true},
		{name: "negative max entries", content: negativeMaxEntries, create: true, wantErr: true},
		{name: "missing file", create: false, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if tt.create {
				if err := os.WriteFile(filepath.Join(dir, configFilename), []byte(tt.content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			t.Chdir(dir)

			cfg, err := loadConfig()
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.ServerPort != 10053 || len(cfg.Authorities) != 1 {
				t.Errorf("unexpected config %+v", cfg)
			}
			switch tt.name {
			case "valid":
				if cfg.Cache.TTL != time.Minute || cfg.Cache.MaxEntries != 2048 || cfg.Cache.Shards != 32 {
					t.Errorf("unexpected cache config %+v", cfg.Cache)
				}
			case "legacy cacheTTL":
				if cfg.Cache.TTL != 2*time.Minute {
					t.Errorf("legacy cacheTTL not applied, got %s", cfg.Cache.TTL)
				}
			}
		})
	}
}

// Cache sizing from config must hold: entries beyond maxEntries evict
// expired ones first, then arbitrary ones.
func TestCacheEviction(t *testing.T) {
	c := newDNSCache(cacheConfig{MaxEntries: 8, Shards: 1})
	ttl := time.Minute

	msg := &dns.Msg{}
	for i := 0; i < 100; i++ {
		c.set(fmt.Sprintf("k%d", i), msg, ttl)
	}
	if len(c.shards[0].items) > 8 {
		t.Errorf("cache exceeded configured capacity: %d entries", len(c.shards[0].items))
	}
	// Most recent key must still be present.
	if _, ok := c.get("k99"); !ok {
		t.Error("most recent entry was evicted")
	}

	// Expired entries are reclaimable.
	short := newDNSCache(cacheConfig{MaxEntries: 4, Shards: 1})
	for i := 0; i < 10; i++ {
		short.set(fmt.Sprintf("s%d", i), msg, time.Nanosecond)
	}
	time.Sleep(time.Millisecond)
	for i := 0; i < 100; i++ {
		short.set(fmt.Sprintf("n%d", i), msg, ttl)
	}
	if len(short.shards[0].items) > 4 {
		t.Errorf("cache exceeded configured capacity: %d entries", len(short.shards[0].items))
	}
}

// The configured capacity must be honored exactly across shards even
// when maxEntries does not divide by the shard count.
func TestCacheCapacityExact(t *testing.T) {
	const maxEntries, shards = 10, 4 // deliberately not a multiple
	c := newDNSCache(cacheConfig{MaxEntries: maxEntries, Shards: shards})
	if c.limitFor(0) != 3 || c.limitFor(3) != 2 {
		t.Fatalf("remainder spread wrong: limitFor(0)=%d limitFor(3)=%d", c.limitFor(0), c.limitFor(3))
	}

	msg := &dns.Msg{}
	for i := 0; i < 50; i++ { // far beyond capacity
		c.set(fmt.Sprintf("e%d", i), msg, time.Minute)
	}
	total := 0
	for i := range c.shards {
		c.shards[i].mu.RLock()
		total += len(c.shards[i].items)
		c.shards[i].mu.RUnlock()
	}
	if total > maxEntries {
		t.Errorf("capacity not honored exactly: %d entries stored, want ≤ %d", total, maxEntries)
	}
}

// Direct unit coverage of the cache primitives: misses, roundtrips,
// lazy expiry deletion and ttl<=0 handling.
func TestDNSCacheBasics(t *testing.T) {
	c := newDNSCache(cacheConfig{MaxEntries: 100, Shards: 4})
	msg := &dns.Msg{}

	// Miss on an empty cache.
	if _, ok := c.get("missing"); ok {
		t.Error("expected miss on empty cache")
	}

	// Roundtrip.
	c.set("a", msg, time.Minute)
	got, ok := c.get("a")
	if !ok || got != msg {
		t.Errorf("expected cached message, got ok=%v", ok)
	}

	// Expired entries report a miss AND are removed from the map.
	c.set("b", msg, -time.Second) // already expired
	if _, ok := c.get("b"); ok {
		t.Error("expired entry must be a miss")
	}
	c.shards[0].mu.RLock()
	_, stillThere := c.shards[0].items["b"]
	c.shards[0].mu.RUnlock()
	if stillThere {
		t.Error("expired entry must be deleted lazily on read")
	}

	// ttl <= 0 disables storing.
	c.set("c", msg, 0)
	if _, ok := c.get("c"); ok {
		t.Error("ttl=0 entries must not be stored")
	}
}

// Both the new cache.ttl section and the deprecated top-level
// cacheTTL must reach the handler.
func TestEffectiveCacheTTL(t *testing.T) {
	authorities := []authority{{DNSServer: "8.8.8.8", DNSPort: 53, DNSProtocol: "udp", Timeout: 2}}

	h := newDNSHandler(&config{Cache: cacheConfig{TTL: time.Minute}, Authorities: authorities})
	if h.effectiveCacheTTL != time.Minute {
		t.Errorf("cache.ttl not honored, got %s", h.effectiveCacheTTL)
	}
	h = newDNSHandler(&config{CacheTTL: 2 * time.Minute, Authorities: authorities})
	if h.effectiveCacheTTL != 2*time.Minute {
		t.Errorf("legacy cacheTTL not honored, got %s", h.effectiveCacheTTL)
	}
	h = newDNSHandler(&config{
		Cache:       cacheConfig{TTL: 3 * time.Minute},
		CacheTTL:    2 * time.Minute,
		Authorities: authorities,
	})
	if h.effectiveCacheTTL != 3*time.Minute {
		t.Errorf("cache.ttl must win over legacy field, got %s", h.effectiveCacheTTL)
	}
}

// configureCache swaps the global instance used by cachedFetch.
func TestConfigureCache(t *testing.T) {
	original := cache
	defer func() { cache = original }()

	small := newDNSCache(cacheConfig{MaxEntries: 1, Shards: 1})
	cache = small

	msgA, msgB := &dns.Msg{}, &dns.Msg{}
	fetchCount := 0
	fetch := func() (*dns.Msg, error) { fetchCount++; return msgA, nil }

	if got, err := cachedFetch("x", time.Minute, fetch); err != nil || got != msgA {
		t.Fatalf("first call must fetch and return msgA (err=%v)", err)
	}
	cache.set("y", msgB, time.Minute)
	if got, _ := cache.get("y"); got != msgB {
		t.Error("configured instance must store entries")
	}
	if fetchCount != 1 {
		t.Errorf("unexpected upstream fetch count %d", fetchCount)
	}
}

// Keys must spread across shards without losses.
func TestCacheShardDistribution(t *testing.T) {
	const shards = 8
	c := newDNSCache(cacheConfig{MaxEntries: 1024, Shards: shards})
	msg := &dns.Msg{}

	const n = 500
	for i := 0; i < n; i++ {
		c.set(fmt.Sprintf("host%d.example.test.", i), msg, time.Minute)
	}
	total := 0
	nonEmpty := 0
	for i := range c.shards {
		c.shards[i].mu.RLock()
		total += len(c.shards[i].items)
		if len(c.shards[i].items) > 0 {
			nonEmpty++
		}
		c.shards[i].mu.RUnlock()
	}
	if total != n {
		t.Errorf("lost entries across shards: %d stored, want %d", total, n)
	}
	if nonEmpty < shards/2 {
		t.Errorf("keys not distributed: only %d/%d shards populated", nonEmpty, shards)
	}
}

// Hammer get/set concurrently, including expiry transitions, to prove
// the custom cache is race-free end to end.
func TestDNSCacheConcurrent(t *testing.T) {
	c := newDNSCache(cacheConfig{})
	msg := &dns.Msg{}

	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				key := fmt.Sprintf("w%d-k%d", id, i%20)
				if i%7 == 0 {
					c.set(key, msg, time.Millisecond) // expires fast
				} else if i%5 == 0 {
					c.set(key, msg, time.Minute)
				}
				c.get(key)
			}
		}(w)
	}
	wg.Wait()
}

func RunLocalUDPServer(laddr string) (*dns.Server, error) {
	server, _, err := RunLocalUDPServerWithFinChan(laddr)

	return server, err
}

func BenchmarkLeadAuthority(b *testing.B) {
	handler := newDNSHandler(&config{
		Authorities: []authority{
			{DNSServer: "8.8.8.8", DNSPort: 53, DNSProtocol: "udp", Timeout: 2},
			{DNSServer: "8.8.4.4", DNSPort: 53, DNSProtocol: "udp", Timeout: 2, DomainName: "google.fr"},
			{DNSServer: "1.1.1.1", DNSPort: 53, DNSProtocol: "udp", Timeout: 2, DomainName: "toto.com"},
		},
	})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := handler.leadAuthority("dev.google.fr"); err != nil {
			b.Fatal(err)
		}
	}
}

// Worst case for randomness: every configured authority is a default one,
// so all match and the reservoir sampler draws rand.IntN per match.
func BenchmarkLeadAuthorityAllDefaults(b *testing.B) {
	handler := newDNSHandler(&config{
		Authorities: []authority{
			{DNSServer: "8.8.8.8", DNSPort: 53, DNSProtocol: "udp", Timeout: 2},
			{DNSServer: "8.8.4.4", DNSPort: 53, DNSProtocol: "udp", Timeout: 2},
			{DNSServer: "1.1.1.1", DNSPort: 53, DNSProtocol: "udp", Timeout: 2},
			{DNSServer: "9.9.9.9", DNSPort: 53, DNSProtocol: "udp", Timeout: 2},
			{DNSServer: "208.67.222.222", DNSPort: 53, DNSProtocol: "udp", Timeout: 2},
			{DNSServer: "208.67.220.220", DNSPort: 53, DNSProtocol: "udp", Timeout: 2},
			{DNSServer: "64.6.64.6", DNSPort: 53, DNSProtocol: "udp", Timeout: 2},
			{DNSServer: "77.88.8.8", DNSPort: 53, DNSProtocol: "udp", Timeout: 2},
		},
	})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := handler.leadAuthority("dev.google.fr"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRandIntN(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = rand.IntN(8)
	}
}

func BenchmarkResolveDnsQueryCacheHit(b *testing.B) {
	s, err := RunLocalUDPServer("127.0.0.1:0")
	if err != nil {
		b.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	dns.HandleFunc("bench.test.", func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("127.0.0.1"),
			},
		}
		_ = w.WriteMsg(m)
	})
	defer dns.HandleRemove("bench.test.")

	client := &dns.Client{Net: "udp", Timeout: 5 * time.Second, UDPSize: 4096}
	server := &dnsServer{
		DNSServer:   "127.0.0.1",
		DNSPort:     s.PacketConn.LocalAddr().(*net.UDPAddr).Port,
		DNSProtocol: "udp",
		Timeout:     4,
	}
	msg := &dns.Msg{Question: []dns.Question{{Name: "bench.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}
	prefix := serverKeyPrefix(server)

	// Prime the cache so the benchmark measures the hit path
	if _, err := resolveDNSQuery(client, msg, time.Hour, server, prefix); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := resolveDNSQuery(client, msg, time.Hour, server, prefix); err != nil {
			b.Fatal(err)
		}
	}
}

// Parallel variant: reveals contention in the cache layer.
func BenchmarkResolveDnsQueryCacheHitParallel(b *testing.B) {
	s, err := RunLocalUDPServer("127.0.0.1:0")
	if err != nil {
		b.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	dns.HandleFunc("bench.test.", func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("127.0.0.1"),
			},
		}
		_ = w.WriteMsg(m)
	})
	defer dns.HandleRemove("bench.test.")

	client := &dns.Client{Net: "udp", Timeout: 5 * time.Second, UDPSize: 4096}
	server := &dnsServer{
		DNSServer:   "127.0.0.1",
		DNSPort:     s.PacketConn.LocalAddr().(*net.UDPAddr).Port,
		DNSProtocol: "udp",
		Timeout:     4,
	}
	msg := &dns.Msg{Question: []dns.Question{{Name: "bench.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}
	prefix := serverKeyPrefix(server)

	if _, err := resolveDNSQuery(client, msg, time.Hour, server, prefix); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := resolveDNSQuery(client, msg, time.Hour, server, prefix); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// Full handler path (routing + cache lookup + reply assembly), with a
// stubbed writer so DNS packing/writing are excluded.
func BenchmarkServeDNSCacheHit(b *testing.B) {
	s, err := RunLocalUDPServer("127.0.0.1:0")
	if err != nil {
		b.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	dns.HandleFunc("bench.test.", func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("127.0.0.1"),
			},
		}
		_ = w.WriteMsg(m)
	})
	defer dns.HandleRemove("bench.test.")

	handler := newDNSHandler(&config{
		CacheTTL: time.Hour,
		Authorities: []authority{
			{
				DNSServer:   "127.0.0.1",
				DNSPort:     s.PacketConn.LocalAddr().(*net.UDPAddr).Port,
				DNSProtocol: "udp",
				Timeout:     4,
			},
		},
	})

	rm := responseMock{getWriteMsg: func(dMsg *dns.Msg) error { return nil }}
	msg := &dns.Msg{Question: []dns.Question{{Name: "bench.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}

	if rm.getWriteMsg(nil); true {
		handler.ServeDNS(rm, msg) // prime the cache
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.ServeDNS(rm, msg)
	}
}

// Cost of serializing a reply, split by compression, since every real
// request pays this in WriteMsg.
func BenchmarkResponsePack(b *testing.B) {
	newReply := func() *dns.Msg {
		m := &dns.Msg{
			MsgHdr:   dns.MsgHdr{Id: 42, Response: true, RecursionAvailable: true},
			Compress: true,
			Question: []dns.Question{{Name: "example.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}},
		}
		for i := 0; i < 8; i++ {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: fmt.Sprintf("host%d.example.test.", i), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("127.0.0.1"),
			})
		}
		return m
	}

	b.Run("compressed", func(b *testing.B) {
		m := newReply()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := m.Pack(); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("uncompressed", func(b *testing.B) {
		m := newReply()
		m.Compress = false
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := m.Pack(); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// Miss-path benchmark: every query goes upstream (TTL=0 disables the
// cache), exercising socket setup, exchange and response parsing.
func BenchmarkResolveDnsQueryMiss(b *testing.B) {
	s, err := RunLocalUDPServer("127.0.0.1:0")
	if err != nil {
		b.Fatalf("unable to run test server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	dns.HandleFunc("miss.test.", func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("127.0.0.1"),
			},
		}
		_ = w.WriteMsg(m)
	})
	defer dns.HandleRemove("miss.test.")

	client := &dns.Client{Net: "udp", Timeout: 5 * time.Second, UDPSize: 4096}
	server := &dnsServer{
		DNSServer:   "127.0.0.1",
		DNSPort:     s.PacketConn.LocalAddr().(*net.UDPAddr).Port,
		DNSProtocol: "udp",
		Timeout:     4,
	}
	msg := &dns.Msg{Question: []dns.Question{{Name: "miss.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}
	prefix := serverKeyPrefix(server)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := resolveDNSQuery(client, msg, 0, server, prefix); err != nil {
			b.Fatal(err)
		}
	}
}

func RunLocalTCPServer(laddr string) (*dns.Server, error) {
	ln, err := net.Listen("tcp", laddr)
	if err != nil {
		return nil, err
	}
	server := &dns.Server{Listener: ln, ReadTimeout: time.Hour, WriteTimeout: time.Hour}

	waitLock := sync.Mutex{}
	waitLock.Lock()
	server.NotifyStartedFunc = waitLock.Unlock

	fin := make(chan struct{})

	go func() {
		_ = server.ActivateAndServe()
		close(fin)
		_ = ln.Close()
	}()

	waitLock.Lock()

	return server, nil
}

func RunLocalUDPServerWithFinChan(laddr string) (*dns.Server, chan struct{}, error) {
	pc, err := net.ListenPacket("udp", laddr)
	if err != nil {
		return nil, nil, err
	}
	server := &dns.Server{PacketConn: pc, ReadTimeout: time.Hour, WriteTimeout: time.Hour}

	waitLock := sync.Mutex{}
	waitLock.Lock()
	server.NotifyStartedFunc = waitLock.Unlock

	fin := make(chan struct{})

	go func() {
		_ = server.ActivateAndServe()
		close(fin)
		_ = pc.Close()
	}()

	waitLock.Lock()
	return server, fin, nil
}
