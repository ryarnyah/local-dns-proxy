package main

import (
	"errors"
	"fmt"
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
				DnsServer:   "8.8.4.4",
				DnsPort:     53,
				DnsProtocol: "udp",
				Timeout:     2,
			},
			{
				DnsServer:   "8.8.8.8",
				DnsPort:     53,
				DnsProtocol: "udp",
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
	if dnsServer.server.DnsServer != "8.8.8.8" {
		t.Error("unable to lead for google.fr")
	}
	dnsServer, err = dnsHandler.leadAuthority("toto.com")
	if err != nil {
		t.Error(err)
	}
	if dnsServer.server.DnsServer != "8.8.4.4" {
		t.Error("unable to lead for toto.com")
	}

	// FQDN with trailing dot and mixed case must still match
	dnsServer, err = dnsHandler.leadAuthority("dev.google.fr.")
	if err != nil {
		t.Error(err)
	}
	if dnsServer.server.DnsServer != "8.8.8.8" {
		t.Error("unable to lead for google.fr.")
	}
	dnsServer, err = dnsHandler.leadAuthority("DEV.GOOGLE.FR.")
	if err != nil {
		t.Error(err)
	}
	if dnsServer.server.DnsServer != "8.8.8.8" {
		t.Error("unable to lead for DEV.GOOGLE.FR.")
	}

	config.Authorities = []authority{
		{
			DnsServer:   "8.8.8.8",
			DnsPort:     53,
			DnsProtocol: "udp",
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
				DnsServer:   "8.8.4.4",
				DnsPort:     53,
				DnsProtocol: "udp",
				Timeout:     2,
			},
			{
				DnsServer:   "8.8.8.8",
				DnsPort:     53,
				DnsProtocol: "udp",
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
		if server.server.DnsServer != "8.8.4.4" {
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
		DnsServer:   "127.0.0.1",
		DnsPort:     s.PacketConn.LocalAddr().(*net.UDPAddr).Port,
		DnsProtocol: "udp",
		Timeout:     4,
	}

	msg := &dns.Msg{}

	dMsg, err := resolveDnsQuery(client, msg, 0, dnsServer)
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
	dMsg, err = resolveDnsQuery(client, msg, 1*time.Minute, dnsServer)
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
	dMsg, err = resolveDnsQuery(client, msg, 1*time.Minute, dnsServer)
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

	dnsServer.DnsServer = "127.0.0.2"

	dMsg, err = resolveDnsQuery(client, msg, 1*time.Minute, dnsServer)
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
		DnsServer:   "127.0.0.1",
		DnsPort:     s.PacketConn.LocalAddr().(*net.UDPAddr).Port,
		DnsProtocol: "udp",
		Timeout:     4,
	}

	aMsg := &dns.Msg{Question: []dns.Question{{Name: "dual.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}
	aaaaMsg := &dns.Msg{Question: []dns.Question{{Name: "dual.test.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}}}

	respA, err := resolveDnsQuery(client, aMsg, time.Minute, server)
	if err != nil {
		t.Fatal(err)
	}
	respAAAA, err := resolveDnsQuery(client, aaaaMsg, time.Minute, server)
	if err != nil {
		t.Fatal(err)
	}
	// Second round must be served from cache without mixing types
	respA2, err := resolveDnsQuery(client, aMsg, time.Minute, server)
	if err != nil {
		t.Fatal(err)
	}
	respAAAA2, err := resolveDnsQuery(client, aaaaMsg, time.Minute, server)
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
		DnsServer:   "127.0.0.1",
		DnsPort:     s.PacketConn.LocalAddr().(*net.UDPAddr).Port,
		DnsProtocol: "udp",
		Timeout:     4,
	}

	msg := &dns.Msg{Question: []dns.Question{{Name: "nx.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}
	dMsg, err := resolveDnsQuery(client, msg, time.Minute, server)
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
		DnsServer:   "127.0.0.1",
		DnsPort:     s.PacketConn.LocalAddr().(*net.UDPAddr).Port,
		DnsProtocol: "udp",
		Timeout:     4,
	}

	msg := &dns.Msg{Question: []dns.Question{{Name: "alias.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}
	dMsg, err := resolveDnsQuery(client, msg, time.Minute, server)
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
		DnsServer:   "127.0.0.1",
		DnsPort:     s.PacketConn.LocalAddr().(*net.UDPAddr).Port,
		DnsProtocol: "udp",
		Timeout:     4,
	}

	msg := &dns.Msg{Question: []dns.Question{{Name: "ttl.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}

	if _, err := resolveDnsQuery(client, msg, 80*time.Millisecond, server); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveDnsQuery(client, msg, 80*time.Millisecond, server); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if fetches != 1 {
		mu.Unlock()
		t.Fatalf("second query must hit cache, got %d upstream fetches", fetches)
	}
	mu.Unlock()

	time.Sleep(150 * time.Millisecond)
	if _, err := resolveDnsQuery(client, msg, 80*time.Millisecond, server); err != nil {
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
		DnsServer:   "127.0.0.1",
		DnsPort:     s.PacketConn.LocalAddr().(*net.UDPAddr).Port,
		DnsProtocol: "udp",
		Timeout:     4,
	}

	msg := &dns.Msg{Question: []dns.Question{{Name: "nocache.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}
	for i := 0; i < 3; i++ {
		if _, err := resolveDnsQuery(client, msg, 0, server); err != nil {
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
				DnsServer:   "127.0.0.1",
				DnsPort:     s.PacketConn.LocalAddr().(*net.UDPAddr).Port,
				DnsProtocol: "udp",
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
		DnsServer:   "127.0.0.1",
		DnsPort:     s.Listener.Addr().(*net.TCPAddr).Port,
		DnsProtocol: "tcp",
		Timeout:     4,
	}

	msg := &dns.Msg{Question: []dns.Question{{Name: "tcp.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}
	dMsg, err := resolveDnsQuery(client, msg, time.Minute, server)
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
		DnsServer:   "127.0.0.1",
		DnsPort:     s.PacketConn.LocalAddr().(*net.UDPAddr).Port,
		DnsProtocol: "udp",
		Timeout:     1,
	}

	msg := &dns.Msg{Question: []dns.Question{{Name: "slow.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}

	start := time.Now()
	dMsg, err := resolveDnsQuery(client, msg, 0, server)
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
				DnsServer:   "127.0.0.1",
				DnsPort:     s.PacketConn.LocalAddr().(*net.UDPAddr).Port,
				DnsProtocol: "udp",
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
				DnsServer:   "8.8.8.8",
				DnsPort:     53,
				DnsProtocol: "udp",
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
cacheTTL: 1m
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
	emptyDnsServer := `---
serverPort: 10053
serverProtocol: udp
authorities:
  - dnsPort: 53
    dnsProtocol: udp
    timeout: 2
`
	badDnsPort := `---
serverPort: 10053
serverProtocol: udp
authorities:
  - dnsServer: 8.8.8.8
    dnsPort: 0
    dnsProtocol: udp
    timeout: 2
`
	badDnsProtocol := `---
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
		{name: "invalid yaml", content: invalidYaml, create: true, wantErr: true},
		{name: "no authorities", content: noAuthorities, create: true, wantErr: true},
		{name: "zero timeout", content: zeroTimeout, create: true, wantErr: true},
		{name: "bad protocol", content: badProtocol, create: true, wantErr: true},
		{name: "bad port", content: badPort, create: true, wantErr: true},
		{name: "empty dns server", content: emptyDnsServer, create: true, wantErr: true},
		{name: "bad dns port", content: badDnsPort, create: true, wantErr: true},
		{name: "bad dns protocol", content: badDnsProtocol, create: true, wantErr: true},
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
			if cfg.CacheTTL != time.Minute {
				t.Errorf("unexpected cacheTTL %s", cfg.CacheTTL)
			}
		})
	}
}

func RunLocalUDPServer(laddr string) (*dns.Server, error) {
	server, _, err := RunLocalUDPServerWithFinChan(laddr)

	return server, err
}

func BenchmarkLeadAuthority(b *testing.B) {
	handler := newDNSHandler(&config{
		Authorities: []authority{
			{DnsServer: "8.8.8.8", DnsPort: 53, DnsProtocol: "udp", Timeout: 2},
			{DnsServer: "8.8.4.4", DnsPort: 53, DnsProtocol: "udp", Timeout: 2, DomainName: "google.fr"},
			{DnsServer: "1.1.1.1", DnsPort: 53, DnsProtocol: "udp", Timeout: 2, DomainName: "toto.com"},
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
		DnsServer:   "127.0.0.1",
		DnsPort:     s.PacketConn.LocalAddr().(*net.UDPAddr).Port,
		DnsProtocol: "udp",
		Timeout:     4,
	}
	msg := &dns.Msg{Question: []dns.Question{{Name: "bench.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}

	// Prime the cache so the benchmark measures the hit path
	if _, err := resolveDnsQuery(client, msg, time.Hour, server); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := resolveDnsQuery(client, msg, time.Hour, server); err != nil {
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
