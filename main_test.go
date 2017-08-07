package main

import (
	"net"
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
			authority{
				DnsServer:   "8.8.4.4",
				DnsPort:     53,
				DnsProtocol: "udp",
				Timeout:     2,
			},
			authority{
				DnsServer:   "8.8.8.8",
				DnsPort:     53,
				DnsProtocol: "udp",
				Timeout:     2,
				DomainName:  "google.fr",
			},
		},
	}
	dnsHandler := &dnsHandler{
		config: config,
	}

	dnsServer, err := dnsHandler.leadAuthority("dev.google.fr")
	if err != nil {
		t.Error(err)
	}
	if dnsServer.DnsServer != "8.8.8.8" {
		t.Error("unable to lead for google.fr")
	}
	dnsServer, err = dnsHandler.leadAuthority("toto.com")
	if err != nil {
		t.Error(err)
	}
	if dnsServer.DnsServer != "8.8.4.4" {
		t.Error("unable to lead for toto.com")
	}

	config.Authorities = []authority{
		authority{
			DnsServer:   "8.8.8.8",
			DnsPort:     53,
			DnsProtocol: "udp",
			Timeout:     2,
			DomainName:  "google.fr",
		},
	}

	dnsServer, err = dnsHandler.leadAuthority("toto.com")
	if err == nil {
		t.Error("unable to not find authority")
	}
	if dnsServer != nil {
		t.Error("unable to not find authority")
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
			dns.Question{
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
	if len(dMsg.Answer) > 0 && dMsg.Answer[0].(*dns.A).A.To4().String() != "127.0.0.1" {
		t.Fail()
	}
	dns.HandleRemove("toto.com.")
	// Test cache without handler
	dMsg, err = resolveDnsQuery(client, msg, 1*time.Minute, dnsServer)
	if err != nil {
		t.Fail()
	}
	if len(dMsg.Answer) > 0 && dMsg.Answer[0].(*dns.A).A.To4().String() != "127.0.0.1" {
		t.Fail()
	}

	// Test fail
	msg = &dns.Msg{
		Question: []dns.Question{
			dns.Question{
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
	if dMsg.Rcode != dns.RcodeNameError {
		t.Fail()
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
			authority{
				DnsServer:   "127.0.0.1",
				DnsPort:     s.PacketConn.LocalAddr().(*net.UDPAddr).Port,
				DnsProtocol: "udp",
				Timeout:     2,
			},
		},
	}
	dnsHandler := &dnsHandler{
		config: config,
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
	defer dns.HandleRemove("toto.com.")

	msg := &dns.Msg{
		Question: []dns.Question{
			dns.Question{
				Name:   "toto.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			},
		},
	}

	rm := responseMock{
		getWriteMsg: func(dMsg *dns.Msg) error {
			if len(dMsg.Answer) > 0 && dMsg.Answer[0].(*dns.A).A.To4().String() != "127.0.0.1" {
				t.Fail()
			}
			return nil
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
		return e.getLocalAddr()
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

func RunLocalUDPServer(laddr string) (*dns.Server, error) {
	server, _, err := RunLocalUDPServerWithFinChan(laddr)

	return server, err
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

	fin := make(chan struct{}, 0)

	go func() {
		_ = server.ActivateAndServe()
		close(fin)
		_ = pc.Close()
	}()

	waitLock.Lock()
	return server, fin, nil
}
