//go:build go1.24

package tls

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

const (
	testECHPublicName = "public.example"
	testECHInnerName  = "inner.example"
	testECHOuterName  = "override.example"
)

// newTestECHKey returns a single-config ECHConfigList and its server key.
func newTestECHKey(t *testing.T, publicName string) ([]byte, stdtls.EncryptedClientHelloKey) {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var b cryptobyte.Builder
	b.AddUint16(extensionEncryptedClientHello)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(7)       // config_id
		b.AddUint16(0x0020) // DHKEM(X25519, HKDF-SHA256)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(priv.PublicKey().Bytes()) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16(0x0001) // HKDF-SHA256
			b.AddUint16(0x0001) // AES-128-GCM
		})
		b.AddUint8(0) // maximum_name_length
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(publicName)) })
		b.AddUint16(0) // extensions
	})
	config := b.BytesOrPanic()
	var list cryptobyte.Builder
	list.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(config) })
	return list.BytesOrPanic(), stdtls.EncryptedClientHelloKey{Config: config, PrivateKey: priv.Bytes(), SendAsRetry: true}
}

func newTestCert(t *testing.T, names ...string) stdtls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return stdtls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// helloRecordingConn captures everything the client writes.
type helloRecordingConn struct {
	net.Conn
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *helloRecordingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.buf.Write(p)
	c.mu.Unlock()
	return c.Conn.Write(p)
}

// outerSNI parses the SNI of the first ClientHello record the client wrote.
func (c *helloRecordingConn) outerSNI(t *testing.T) string {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	raw := c.buf.Bytes()
	if len(raw) < 5 || raw[0] != byte(recordTypeHandshake) {
		t.Fatalf("first record is not a handshake record")
	}
	n := int(raw[3])<<8 | int(raw[4])
	var hello clientHelloMsg
	if !hello.unmarshal(raw[5 : 5+n]) {
		t.Fatal("cannot parse outer ClientHello")
	}
	if len(hello.encryptedClientHello) == 0 {
		t.Fatal("outer ClientHello has no encrypted_client_hello extension")
	}
	return hello.serverName
}

type echHandshakeResult struct {
	outerSNI       string
	serverSawInner string
	accepted       bool
}

func runECHHandshake(t *testing.T, id ClientHelloID, outerOverride string) echHandshakeResult {
	t.Helper()
	configList, key := newTestECHKey(t, testECHPublicName)
	serverConf := &stdtls.Config{
		Certificates:             []stdtls.Certificate{newTestCert(t, testECHInnerName, testECHPublicName)},
		EncryptedClientHelloKeys: []stdtls.EncryptedClientHelloKey{key},
		MinVersion:               stdtls.VersionTLS13,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serverName := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			serverName <- ""
			return
		}
		defer c.Close()
		sc := stdtls.Server(c, serverConf)
		if err := sc.Handshake(); err != nil {
			serverName <- ""
			return
		}
		serverName <- sc.ConnectionState().ServerName
		_, _ = sc.Write([]byte("ok"))
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	rec := &helloRecordingConn{Conn: raw}
	uc := UClient(rec, &Config{
		ServerName:                     testECHInnerName,
		InsecureSkipVerify:             true,
		MinVersion:                     VersionTLS13,
		EncryptedClientHelloConfigList: configList,
		ECHOuterServerName:             outerOverride,
	}, id)
	defer uc.Close()
	if err := uc.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	buf := make([]byte, 2)
	if _, err := uc.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	return echHandshakeResult{
		outerSNI:       rec.outerSNI(t),
		serverSawInner: <-serverName,
		accepted:       uc.ConnectionState().ECHAccepted,
	}
}

func TestECHOuterServerName(t *testing.T) {
	ids := map[string]ClientHelloID{
		"golang":  HelloGolang,
		"chrome":  HelloChrome_Auto,
		"firefox": HelloFirefox_Auto,
	}
	for name, id := range ids {
		t.Run(name+"/override", func(t *testing.T) {
			r := runECHHandshake(t, id, testECHOuterName)
			if r.outerSNI != testECHOuterName {
				t.Errorf("outer SNI = %q, want %q", r.outerSNI, testECHOuterName)
			}
			if !r.accepted {
				t.Error("ECH not accepted")
			}
			if r.serverSawInner != testECHInnerName {
				t.Errorf("server saw SNI %q, want %q", r.serverSawInner, testECHInnerName)
			}
		})
		t.Run(name+"/default", func(t *testing.T) {
			r := runECHHandshake(t, id, "")
			if r.outerSNI != testECHPublicName {
				t.Errorf("outer SNI = %q, want %q", r.outerSNI, testECHPublicName)
			}
			if !r.accepted {
				t.Error("ECH not accepted")
			}
		})
	}
}

// cloudflareECHConfigList is the ECHConfigList from cloudflare-ech.com's
// HTTPS record on 2026-10-29. A stale list is recovered from the edge's
// retry_configs.
const cloudflareECHConfigList = "AEX+DQBBZwAgACDh2F7hiRwFUFy6AsJFLrJP94/M2W65VkT5LkKwFnngMgAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA="

func dialCloudflareECH(t *testing.T, id ClientHelloID, inner, outer string) (ConnectionState, error) {
	t.Helper()
	list, _ := base64.StdEncoding.DecodeString(cloudflareECHConfigList)
	for attempt := 0; attempt < 2; attempt++ {
		raw, err := net.DialTimeout("tcp", "cloudflare-ech.com:443", 10*time.Second)
		if err != nil {
			t.Skipf("cannot reach Cloudflare: %v", err)
		}
		rec := &helloRecordingConn{Conn: raw}
		_ = rec.SetDeadline(time.Now().Add(10 * time.Second))
		uc := UClient(rec, &Config{
			ServerName:                     inner,
			MinVersion:                     VersionTLS13,
			EncryptedClientHelloConfigList: list,
			ECHOuterServerName:             outer,
		}, id)
		err = uc.Handshake()
		state := uc.ConnectionState()
		var sni string
		if rec.buf.Len() > 0 {
			sni = rec.outerSNI(t)
		}
		uc.Close()
		var rejection *ECHRejectionError
		if errors.As(err, &rejection) && len(rejection.RetryConfigList) > 0 && attempt == 0 {
			list = rejection.RetryConfigList
			continue
		}
		if err == nil && outer != "" && sni != outer {
			t.Errorf("outer SNI on the wire = %q, want %q", sni, outer)
		}
		return state, err
	}
	return ConnectionState{}, errors.New("unreachable")
}

// TestECHOuterServerNameCloudflare checks Cloudflare's live outer-name policy.
// Set UTLS_ECH_LIVE=1 to run it.
func TestECHOuterServerNameCloudflare(t *testing.T) {
	if os.Getenv("UTLS_ECH_LIVE") == "" {
		t.Skip("set UTLS_ECH_LIVE=1 to dial Cloudflare")
	}
	for _, tc := range []struct {
		outer  string
		accept bool
	}{
		{"", true},
		{"cloudflare-esni.com", true},
		{"cloudflare.com", false},
		{"example.com", false},
	} {
		for name, id := range map[string]ClientHelloID{"golang": HelloGolang, "chrome": HelloChrome_Auto} {
			t.Run(name+"/"+tc.outer, func(t *testing.T) {
				state, err := dialCloudflareECH(t, id, "cloudflare-dns.com", tc.outer)
				if tc.accept {
					if err != nil || !state.ECHAccepted {
						t.Fatalf("want ECH accepted, got accepted=%v err=%v", state.ECHAccepted, err)
					}
					if state.ServerName != "cloudflare-dns.com" {
						t.Errorf("ServerName = %q", state.ServerName)
					}
					return
				}
				if err == nil && state.ECHAccepted {
					t.Fatalf("outer %q unexpectedly accepted", tc.outer)
				}
				t.Logf("outer %q refused as expected: %v", tc.outer, err)
			})
		}
	}
}

// startECHRejectionServer serves certNames over a key the client's stale
// config does not match, and returns a dial func and a fresh config list.
func startECHRejectionServer(t *testing.T, certNames ...string) (dial func(list []byte) error, staleList []byte) {
	t.Helper()
	_, key := newTestECHKey(t, testECHPublicName)
	staleList, _ = newTestECHKey(t, testECHPublicName)
	cert := newTestCert(t, certNames...)
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	ln, err := stdtls.Listen("tcp", "127.0.0.1:0", &stdtls.Config{
		Certificates:             []stdtls.Certificate{cert},
		EncryptedClientHelloKeys: []stdtls.EncryptedClientHelloKey{key},
		NextProtos:               []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.(*stdtls.Conn).Handshake()
			}()
		}
	}()
	dial = func(list []byte) error {
		raw, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		uc := UClient(raw, &Config{
			ServerName:                     testECHInnerName,
			RootCAs:                        roots,
			EncryptedClientHelloConfigList: list,
			ECHOuterServerName:             testECHOuterName,
		}, HelloChrome_Auto)
		return uc.Handshake()
	}
	return dial, staleList
}

// TestECHRejectionRetryConfigsWithParrotALPN checks that a parrot's ALPN
// extension does not break the rejection handshake, so a stale config still
// yields retry configs.
func TestECHRejectionRetryConfigsWithParrotALPN(t *testing.T) {
	dial, staleList := startECHRejectionServer(t, testECHOuterName, testECHInnerName)
	var rejection *ECHRejectionError
	if err := dial(staleList); !errors.As(err, &rejection) || len(rejection.RetryConfigList) == 0 {
		t.Fatalf("stale config: got %v, want ECHRejectionError with retry configs", err)
	}
	if err := dial(rejection.RetryConfigList); err != nil {
		t.Fatalf("retry: %v", err)
	}
}

// TestECHRejectionVerifiesOuterName checks that the rejection handshake is
// authenticated against the outer name, the only name the server answers for
// before ECH is accepted.
func TestECHRejectionVerifiesOuterName(t *testing.T) {
	t.Run("outer-only", func(t *testing.T) {
		dial, staleList := startECHRejectionServer(t, testECHOuterName)
		var rejection *ECHRejectionError
		if err := dial(staleList); !errors.As(err, &rejection) || len(rejection.RetryConfigList) == 0 {
			t.Fatalf("got %v, want ECHRejectionError with retry configs", err)
		}
	})
	t.Run("inner-only", func(t *testing.T) {
		dial, staleList := startECHRejectionServer(t, testECHInnerName)
		var verifyErr *CertificateVerificationError
		if err := dial(staleList); !errors.As(err, &verifyErr) {
			t.Fatalf("got %v, want CertificateVerificationError", err)
		}
	})
}

func TestECHOuterServerNameRejectsInvalidName(t *testing.T) {
	configList, _ := newTestECHKey(t, testECHPublicName)
	for _, name := range []string{"192.0.2.1", "override.example.", "bad name"} {
		for idName, id := range map[string]ClientHelloID{"golang": HelloGolang, "chrome": HelloChrome_Auto} {
			client, server := net.Pipe()
			uc := UClient(client, &Config{
				ServerName:                     testECHInnerName,
				InsecureSkipVerify:             true,
				EncryptedClientHelloConfigList: configList,
				ECHOuterServerName:             name,
			}, id)
			go func() { _, _ = io.Copy(io.Discard, server) }()
			_ = client.SetDeadline(time.Now().Add(2 * time.Second))
			if err := uc.Handshake(); err == nil || !strings.Contains(err.Error(), "ECHOuterServerName") {
				t.Errorf("%s/%q: got %v, want an ECHOuterServerName error", idName, name, err)
			}
			client.Close()
			server.Close()
		}
	}
}
