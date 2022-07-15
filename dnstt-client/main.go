// dnstt-client is the client end of a DNS tunnel.
//
// Usage:
//     dnstt-client [-doh URL|-dot ADDR|-udp ADDR]
//
// Examples:
//     dnstt-client -doh https://resolver.example/dns-query t.example.com
//     dnstt-client -dot resolver.example:853 t.example.com
//
// The program supports DNS over HTTPS (DoH), DNS over TLS (DoT), and UDP DNS.
// Use one of these options:
//     -doh https://resolver.example/dns-query
//     -dot resolver.example:853
//     -udp resolver.example:53
//
// You can give the server's public key as a file or as a hex string. Use
// "dnstt-server -gen-key" to get the public key.
//     -pubkey-file server.pub
//     -pubkey 0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff
//
// DOMAIN is the root of the DNS zone reserved for the tunnel. See README for
// instructions on setting it up.
//
// In -doh and -dot modes, the program's TLS fingerprint is camouflaged with
// uTLS by default. The specific TLS fingerprint is selected randomly from a
// weighted distribution. You can set your own distribution (or specific single
// fingerprint) using the -utls option. The special value "none" disables uTLS.
//     -utls '3*Firefox,2*Chrome,1*iOS'
//     -utls Firefox
//     -utls none
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	dc "www.bamsoftware.com/git/dnstt.git/dnstt-client/lib"
)

func main() {
	var utlsDistribution string

	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), `Usage:
  %[1]s [-utls FINGERPRINTS]

`, os.Args[0])
		flag.PrintDefaults()
		labels := make([]string, 0, len(dc.UtlsClientHelloIDMap))
		labels = append(labels, "none")
		for _, entry := range dc.UtlsClientHelloIDMap {
			labels = append(labels, entry.Label)
		}
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), `
Known TLS fingerprints for -utls are:
`)
		i := 0
		for i < len(labels) {
			var line strings.Builder
			_, _ = fmt.Fprintf(&line, "  %s", labels[i])
			w := 2 + len(labels[i])
			i++
			for i < len(labels) && w+1+len(labels[i]) <= 72 {
				_, _ = fmt.Fprintf(&line, " %s", labels[i])
				w += 1 + len(labels[i])
				i++
			}
			_, _ = fmt.Fprintln(flag.CommandLine.Output(), line.String())
		}
	}
	flag.StringVar(&utlsDistribution, "utls",
		"3*Firefox_65,1*Firefox_63,1*iOS_12_1",
		"choose TLS fingerprint from weighted distribution")
	flag.Parse()

	if flag.NArg() != 0 {
		flag.Usage()
		os.Exit(1)
	}

	utlsClientHelloID, err := dc.SampleUTLSDistribution(utlsDistribution)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "parsing -utls: %v\n", err)
		os.Exit(1)
	}

	dc.Start("", utlsClientHelloID)
}
