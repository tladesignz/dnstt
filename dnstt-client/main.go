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
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	pt "git.torproject.org/pluggable-transports/goptlib.git"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	dc "www.bamsoftware.com/git/dnstt.git/dnstt-client/lib"

	utls "github.com/refraction-networking/utls"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/noise"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

// smux streams will be closed after this much time without receiving data.
const idleTimeout = 2 * time.Minute

// dnsNameCapacity returns the number of bytes remaining for encoded data after
// including domain in a DNS name.
func dnsNameCapacity(domain dns.Name) int {
	// Names must be 255 octets or shorter in total length.
	// https://tools.ietf.org/html/rfc1035#section-2.3.4
	capacity := 255
	// Subtract the length of the null terminator.
	capacity -= 1
	for _, label := range domain {
		// Subtract the length of the label and the length octet.
		capacity -= len(label) + 1
	}
	// Each label may be up to 63 bytes long and requires 64 bytes to
	// encode.
	capacity = capacity * 63 / 64
	// Base32 expands every 5 bytes to 8.
	capacity = capacity * 5 / 8
	return capacity
}

// sampleUTLSDistribution parses a weighted uTLS Client Hello ID distribution
// string of the form "3*Firefox,2*Chrome,1*iOS", matches each label to a
// utls.ClientHelloID from utlsClientHelloIDMap, and randomly samples one
// utls.ClientHelloID from the distribution.
func sampleUTLSDistribution(spec string) (*utls.ClientHelloID, error) {
	weights, labels, err := dc.ParseWeightedList(spec)
	if err != nil {
		return nil, err
	}
	ids := make([]*utls.ClientHelloID, 0, len(labels))
	for _, label := range labels {
		var id *utls.ClientHelloID
		if label == "none" {
			id = nil
		} else {
			id = dc.UtlsLookup(label)
			if id == nil {
				return nil, fmt.Errorf("unknown TLS fingerprint %q", label)
			}
		}
		ids = append(ids, id)
	}
	return ids[dc.SampleWeighted(weights)], nil
}

func handle(local *net.TCPConn, sess *smux.Session, conv uint32) error {
	stream, err := sess.OpenStream()
	if err != nil {
		return fmt.Errorf("session %08x opening stream: %v", conv, err)
	}
	defer func() {
		log.Printf("end stream %08x:%d", conv, stream.ID())
		_ = stream.Close()
	}()
	log.Printf("begin stream %08x:%d", conv, stream.ID())

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(stream, local)
		if err == io.EOF {
			// smux Stream.Write may return io.EOF.
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy stream←local: %v", conv, stream.ID(), err)
		}
		_ = local.CloseRead()
		_ = stream.Close()
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(local, stream)
		if err == io.EOF {
			// smux Stream.WriteTo may return io.EOF.
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy local←stream: %v", conv, stream.ID(), err)
		}
		_ = local.CloseWrite()
	}()
	wg.Wait()

	return err
}

func acceptLoop(ln *pt.SocksListener, pconn net.PacketConn, remoteAddr net.Addr, shutdown chan struct{}, wg *sync.WaitGroup) {
	defer func() {
		_ = ln.Close()
		_ = pconn.Close()
	}()

	for {
		local, err := ln.AcceptSocks()
		if err != nil {
			//goland:noinspection GoDeprecation
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}

			log.Printf("SOCKS accept error: %s", err)
			break
		}
		log.Printf("SOCKS accepted: %v", local.Req)

		wg.Add(1)
		go func() {
			defer func() {
				_ = local.Close()
				wg.Done()
			}()

			var pubkey []byte

			if arg, ok := local.Req.Args.Get("pubkey"); ok {
				pubkey, err = noise.DecodeKey(arg)
				if err != nil {
					log.Printf("pubkey format error: %v", err)
					_ = local.Reject()
					return
				}
			} else {
				log.Print("Missing pubkey")
				_ = local.Reject()
				return
			}

			var domain dns.Name

			if arg, ok := local.Req.Args.Get("domain"); ok {
				domain, err = dns.ParseName(arg)
				if err != nil {
					log.Printf("invalid domain %+q: %v\n", arg, err)
					_ = local.Reject()
					return
				}
			} else {
				log.Print("Missing domain")
				_ = local.Reject()
				return
			}

			mtu := dnsNameCapacity(domain) - 8 - 1 - dc.NumPadding - 1 // clientid + padding length prefix + padding + data length prefix
			if mtu < 80 {
				log.Printf("domain %s leaves only %d bytes for payload", domain, mtu)

				_ = local.Reject()

				return
			}
			log.Printf("effective MTU %d", mtu)

			pconn = dc.NewDNSPacketConn(pconn, remoteAddr, domain)

			defer func() {
				_ = pconn.Close()
			}()

			// Open a KCP conn on the PacketConn.
			conn, err := kcp.NewConn2(remoteAddr, nil, 0, 0, pconn)
			if err != nil {
				log.Printf("opening KCP conn: %v", err)

				_ = local.Reject()

				return
			}
			log.Printf("begin session %08x", conn.GetConv())

			defer func() {
				log.Printf("end session %08x", conn.GetConv())
				_ = conn.Close()
			}()

			// Permit coalescing the payloads of consecutive sends.
			conn.SetStreamMode(true)
			// Disable the dynamic congestion window (limit only by the maximum of
			// local and remote static windows).
			conn.SetNoDelay(
				0, // default nodelay
				0, // default interval
				0, // default resend
				1, // nc=1 => congestion window off
			)
			conn.SetWindowSize(turbotunnel.QueueSize/2, turbotunnel.QueueSize/2)
			if rc := conn.SetMtu(mtu); !rc {
				panic(rc)
			}

			// Put a Noise channel on top of the KCP conn.
			rw, err := noise.NewClient(conn, pubkey)
			if err != nil {
				log.Printf("Opening noise channel: %v", err)

				_ = local.Reject()

				return
			}

			// Start a smux session on the Noise channel.
			smuxConfig := smux.DefaultConfig()
			smuxConfig.Version = 2
			smuxConfig.KeepAliveTimeout = idleTimeout
			smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024 // default is 65536
			sess, err := smux.Client(rw, smuxConfig)
			if err != nil {
				log.Printf("opening smux session: %v", err)

				_ = local.Reject()

				return
			}

			defer func() {
				_ = sess.Close()
			}()

			err = local.Grant(&net.TCPAddr{IP: net.IPv4zero, Port: 0})
			if err != nil {
				log.Printf("conn.Grant error: %s", err)

				return
			}

			handler := make(chan struct{})
			go func() {
				defer close(handler)

				err := handle(local.Conn.(*net.TCPConn), sess, conn.GetConv())
				if err != nil {
					log.Printf("handle: %v", err)
				}
			}()

			select {
			case <-shutdown:
				log.Println("Received shutdown signal")
			case <-handler:
				log.Println("Handler ended")
			}

			return
		}()
	}
}

func main() {
	var dohURL string
	var dotAddr string
	var udpAddr string
	var utlsDistribution string

	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), `Usage:
  %[1]s [-doh URL|-dot ADDR|-udp ADDR]

Examples:
  %[1]s -doh https://resolver.example/dns-query t.example.com
  %[1]s -dot resolver.example:853 t.example.com

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
	flag.StringVar(&dohURL, "doh", "", "URL of DoH resolver")
	flag.StringVar(&dotAddr, "dot", "", "address of DoT resolver")
	flag.StringVar(&udpAddr, "udp", "", "address of UDP DNS resolver")
	flag.StringVar(&utlsDistribution, "utls",
		"3*Firefox_65,1*Firefox_63,1*iOS_12_1",
		"choose TLS fingerprint from weighted distribution")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.LUTC)

	if flag.NArg() != 0 {
		flag.Usage()
		os.Exit(1)
	}

	utlsClientHelloID, err := sampleUTLSDistribution(utlsDistribution)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "parsing -utls: %v\n", err)
		os.Exit(1)
	}
	if utlsClientHelloID != nil {
		log.Printf("uTLS fingerprint %s %s", utlsClientHelloID.Client, utlsClientHelloID.Version)
	}

	// Iterate over the remote resolver address options and select one and
	// only one.
	var remoteAddr net.Addr
	var pconn net.PacketConn
	for _, opt := range []struct {
		s string
		f func(string) (net.Addr, net.PacketConn, error)
	}{
		// -doh
		{dohURL, func(s string) (net.Addr, net.PacketConn, error) {
			addr := turbotunnel.DummyAddr{}
			var rt http.RoundTripper
			if utlsClientHelloID == nil {
				transport := http.DefaultTransport.(*http.Transport).Clone()
				// Disable DefaultTransport's default Proxy =
				// ProxyFromEnvironment setting, for conformity
				// with utlsRoundTripper and with DoT mode,
				// which do not take a proxy from the
				// environment.
				transport.Proxy = nil
				rt = transport
			} else {
				rt = dc.NewUTLSRoundTripper(nil, utlsClientHelloID)
			}
			pconn, err := dc.NewHTTPPacketConn(rt, dohURL, 32)
			return addr, pconn, err
		}},
		// -dot
		{dotAddr, func(s string) (net.Addr, net.PacketConn, error) {
			addr := turbotunnel.DummyAddr{}
			var dialTLSContext func(ctx context.Context, network, addr string) (net.Conn, error)
			if utlsClientHelloID == nil {
				dialTLSContext = (&tls.Dialer{}).DialContext
			} else {
				dialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
					return dc.UtlsDialContext(ctx, network, addr, nil, utlsClientHelloID)
				}
			}
			pconn, err := dc.NewTLSPacketConn(dotAddr, dialTLSContext)
			return addr, pconn, err
		}},
		// -udp
		{udpAddr, func(s string) (net.Addr, net.PacketConn, error) {
			addr, err := net.ResolveUDPAddr("udp", s)
			if err != nil {
				return nil, nil, err
			}
			pconn, err := net.ListenUDP("udp", nil)
			return addr, pconn, err
		}},
	} {
		if opt.s == "" {
			continue
		}
		if pconn != nil {
			_, _ = fmt.Fprintf(os.Stderr, "only one of -doh, -dot, and -udp may be given\n")
			os.Exit(1)
		}
		var err error
		remoteAddr, pconn, err = opt.f(opt.s)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if pconn == nil {
		_, _ = fmt.Fprintf(os.Stderr, "one of -doh, -dot, or -udp is required\n")
		os.Exit(1)
	}

	// Begin goptlib client process.
	ptInfo, err := pt.ClientSetup(nil)
	if err != nil {
		log.Fatal(err)
	}

	if ptInfo.ProxyURL != nil {
		_ = pt.ProxyError("proxy is not supported")
		os.Exit(1)
	}

	listeners := make([]net.Listener, 0)
	shutdown := make(chan struct{})
	var wg sync.WaitGroup

	for _, methodName := range ptInfo.MethodNames {
		switch methodName {
		case "dnstt":
			ln, err := pt.ListenSocks("tcp", "127.0.0.1:0")

			if err != nil {
				_ = pt.CmethodError(methodName, err.Error())
				break
			}

			go acceptLoop(ln, pconn, remoteAddr, shutdown, &wg)

			pt.Cmethod(methodName, ln.Version(), ln.Addr())
			listeners = append(listeners, ln)

		default:
			_ = pt.CmethodError(methodName, "no such method")
		}
	}

	pt.CmethodsDone()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM)

	if os.Getenv("TOR_PT_EXIT_ON_STDIN_CLOSE") == "1" {
		// This environment variable means we should treat EOF on stdin
		// just like SIGTERM: https://bugs.torproject.org/15435.
		go func() {
			if _, err := io.Copy(ioutil.Discard, os.Stdin); err != nil {
				log.Printf("calling io.Copy(ioutil.Discard, os.Stdin) returned error: %v", err)
			}
			log.Printf("synthesizing SIGTERM because of stdin close")
			sigChan <- syscall.SIGTERM
		}()
	}

	// Wait for a signal.
	<-sigChan
	log.Println("stopping dnstt")

	// Signal received, shut down.
	for _, ln := range listeners {
		_ = ln.Close()
	}
	close(shutdown)
	wg.Wait()
	log.Println("dnstt is done.")
}
