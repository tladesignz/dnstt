package main

import (
	"bytes"
	"testing"
	dc "www.bamsoftware.com/git/dnstt.git/dnstt-client/lib"

	"www.bamsoftware.com/git/dnstt.git/dns"
)

func TestDNSNameCapacity(t *testing.T) {
	for domainLen := 0; domainLen < 255; domainLen++ {
		domain, err := dns.NewName(dc.Chunks(bytes.Repeat([]byte{'x'}, domainLen), 63))
		if err != nil {
			continue
		}
		capacity := dnsNameCapacity(domain)
		if capacity <= 0 {
			continue
		}
		prefix := []byte(dc.Base32Encoding.EncodeToString(bytes.Repeat([]byte{'y'}, capacity)))
		labels := append(dc.Chunks(prefix, 63), domain...)
		_, err = dns.NewName(labels)
		if err != nil {
			t.Errorf("length %v  capacity %v  %v", domainLen, capacity, err)
		}
	}
}
