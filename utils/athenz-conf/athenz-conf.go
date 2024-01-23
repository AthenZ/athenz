package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/net/proxy"

	"github.com/AthenZ/athenz/clients/go/zms"
)

var (
	// VERSION gets set by the build script via the LDFLAGS.
	VERSION string

	// BUILD_DATE gets set by the build script via the LDFLAGS.
	BUILD_DATE string
)

func defaultZmsURL() string {
	s := os.Getenv("ZMS")
	if s != "" {
		return s
	}
	return "https://localhost:4443/"
}

func defaultZtsURL() string {
	s := os.Getenv("ZTS")
	if s != "" {
		return s
	}
	return "https://localhost:8443/"
}

func defaultIdentity() string {
	return "user." + os.Getenv("USER")
}

func defaultSocksProxy() string {
	return os.Getenv("SOCKS5_PROXY")
}

// isFreshFile checks the file's last modification time
// and returns true the file was updated within maxAge
// (file is "fresh"), false otherwise (file is "stale").
func isFreshFile(filename string, maxAge float64) bool {
	info, err := os.Stat(filename)
	if err != nil {
		return false
	}
	delta := time.Since(info.ModTime())
	// return false if delta exceeds maxAge
	tooOld := delta.Minutes() > maxAge
	return !tooOld
}

func getCachedNToken() string {
	ntokenFile := os.Getenv("HOME") + "/.ntoken"
	if isFreshFile(ntokenFile, 45) {
		data, err := os.ReadFile(ntokenFile)
		if err == nil {
			return strings.TrimSpace(string(data))
		}
		fmt.Printf("Couldn't read the file, error: %v\n", err)
	}
	return ""
}

const identityPrefix = "user."

func getAuthNToken(identity, authorizedServices, zmsURL string, tr *http.Transport, timeout time.Duration) (string, error) {
	// our identity must be user
	if !strings.HasPrefix(identity, identityPrefix) {
		return "", errors.New("identity must start with " + identityPrefix)
	}
	user := identity[5:]
	ntoken := getCachedNToken()
	if ntoken != "" {
		return ntoken, nil
	}

	fmt.Fprintf(os.Stderr, "Enter password for "+user+": ")
	pass, err := terminal.ReadPassword(syscall.Stdin)
	if err != nil {
		return "", err
	}
	password := string(pass)
	// The user types <return> during terminal.ReadPassword() however
	// since echo is turned off the cursor doesn't make it to the next line.
	fmt.Fprint(os.Stderr, "\n")

	data := []byte(user + ":" + password)
	str := base64.StdEncoding.EncodeToString(data)

	var authHeader = "Authorization"
	var authCreds = "Basic " + str
	zmsClient := zms.ZMSClient{
		URL:          zmsURL,
		Transport:    tr,
		CredsHeaders: make(map[string]string),
		Timeout:      timeout,
	}
	zmsClient.AddCredentials(authHeader, authCreds)
	tok, err := zmsClient.GetUserToken(zms.SimpleName(user), authorizedServices, nil)
	if err != nil {
		return "", fmt.Errorf("Cannot get user token for user: %s error: %v", user, err)
	}
	if tok.Token != "" {
		ntokenFile := os.Getenv("HOME") + "/.ntoken"
		data := []byte(tok.Token)
		os.WriteFile(ntokenFile, data, 0600)
	}
	return string(tok.Token), nil
}

func usage() string {
	var buf bytes.Buffer
	buf.WriteString("usage: athenz-conf -z <zms_url> [flags]\n")
	buf.WriteString(" flags:\n")
	buf.WriteString("   -c cacert_file           CA Certificate file path\n")
	buf.WriteString("   -svc-cert-file cert_file Service Certificate file path\n")
	buf.WriteString("   -f ntoken_file           Principal Authority NToken file used for authentication\n")
	buf.WriteString("   -i identity              User identity to authenticate as if NToken file is not specified\n")
	buf.WriteString("                            (default=" + defaultIdentity() + ")\n")
	buf.WriteString("   -k                       Disable peer verification of SSL certificates.\n")
	buf.WriteString("   -svc-key-file key_file   Service Private Key file path\n")
	buf.WriteString("   -o                       Output config filename (default=athenz.conf)\n")
	buf.WriteString("   -s host:port             The SOCKS5 proxy to route requests through\n")
	buf.WriteString("   -t zts_url               Base URL of the ZTS server to use\n")
	buf.WriteString("                            (default ZTS=" + defaultZtsURL() + ")\n")
	buf.WriteString("   -z zms_url               Base URL of the ZS server to use\n")
	buf.WriteString("                            (default ZMS=" + defaultZmsURL() + ")\n")
	buf.WriteString("   -m timeout               Timeout in seconds for connection requests")
	buf.WriteString("\n")
	return buf.String()
}

func printVersion() {
	if VERSION == "" {
		fmt.Println("athenz-conf (development version)")
	} else {
		fmt.Println("athenz-conf " + VERSION + " " + BUILD_DATE)
	}
}

func loadNtokenFromFile(fileName string) (string, error) {
	buf, err := os.ReadFile(fileName)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(buf)), nil
}

func main() {
	pZMS := flag.String("z", defaultZmsURL(), "Base URL of the ZMS server to use")
	pZTS := flag.String("t", defaultZtsURL(), "Base URL of the ZTS server to use")
	pHdr := flag.String("hdr", "Athenz-Principal-Auth", "the authentication header name")
	pKey := flag.String("svc-key-file", "", "the service private key file")
	pCert := flag.String("svc-cert-file", "", "the service certificate file")
	pIdentity := flag.String("i", defaultIdentity(), "the identity to authenticate as")
	pNtokenFile := flag.String("f", "", "ntoken file path")
	pCACert := flag.String("c", "", "CA Certificate file path")
	pOutputFile := flag.String("o", "athenz.conf", "config filename")
	pSocks := flag.String("s", defaultSocksProxy(), "The SOCKS5 proxy to route requests through, i.e. 127.0.0.1:1080")
	pSkipVerify := flag.Bool("k", false, "Disable peer verification of SSL certificates")
	pTimeout := flag.Int("m", 15, "Timeout in seconds for connection requests")
	pShowVersion := flag.Bool("version", false, "Show version")

	flag.Usage = func() {
		fmt.Println(usage())
	}

	// first we need to parse our arguments based
	// on the flags we defined above

	flag.Parse()

	if *pShowVersion {
		printVersion()
		return
	}

	zmsConfURL := normalizeServerURL(*pZMS, "/zms/v1")
	ztsConfURL := normalizeServerURL(*pZTS, "/zts/v1")
	zmsURL := zmsConfURL + "zms/v1"

	if zmsURL == "" {
		log.Fatalf("No ZMS Url specified")
	}

	// now process our request

	args := flag.Args()
	if len(args) == 1 {
		if args[0] == "help" {
			fmt.Println(usage())
			return
		} else if args[0] == "version" {
			printVersion()
			return
		}
	}

	identity := *pIdentity
	if !strings.Contains(identity, ".") {
		identity = "user." + identity
	}
	if *pSocks == "" {
		pSocks = nil
	}
	if *pCACert == "" {
		pCACert = nil
	}
	if *pKey == "" && *pCert == "" {
		pKey = nil
		pCert = nil
	} else if *pKey == "" || *pCert == "" {
		log.Fatalf("Both service key and certificate must be provided")
	}
	tr := getHttpTransport(pSocks, pKey, pCert, pCACert, *pSkipVerify)
	var ntoken string
	var err error
	if *pNtokenFile == "" {
		if pKey == nil {
			ntoken, err = getAuthNToken(identity, "", zmsURL, tr, time.Duration(time.Duration(*pTimeout)*time.Second))
			if err != nil {
				log.Fatalf("Unable to get NToken: %v", err)
			}
		}
	} else {
		ntoken, err = loadNtokenFromFile(*pNtokenFile)
		if err != nil {
			log.Fatalf("Unable to load ntoken from file: '%s' err: %v", *pNtokenFile, err)
		}
	}
	zmsClient := zms.NewClient(zmsURL, tr)
	zmsClient.Timeout = time.Duration(time.Duration(*pTimeout) * time.Second)
	if ntoken != "" {
		zmsClient.AddCredentials(*pHdr, ntoken)
	}
	var buf bytes.Buffer
	buf.WriteString("{\n")
	buf.WriteString("  \"zmsUrl\": \"" + zmsConfURL + "\",\n")
	if ztsConfURL != "" {
		buf.WriteString("  \"ztsUrl\": \"" + ztsConfURL + "\",\n")
	}

	zmsService, err := zmsClient.GetServiceIdentity(zms.DomainName("sys.auth"), zms.SimpleName("zms"))
	if err != nil {
		log.Fatalf("Unable to retrieve zms service details, err: %v", err)
	}
	dumpService(&buf, "zmsPublicKeys", zmsService)

	ztsService, err := zmsClient.GetServiceIdentity(zms.DomainName("sys.auth"), zms.SimpleName("zts"))
	if err == nil {
		buf.WriteString(",\n")
		dumpService(&buf, "ztsPublicKeys", ztsService)
	}
	buf.WriteString("\n")
	buf.WriteString("}\n")

	err = os.WriteFile(*pOutputFile, buf.Bytes(), 0644)
	if err != nil {
		log.Fatalf("Unable to write athenz.conf file, err: %v", err)
	}
	os.Exit(0)
}

func dumpService(buf *bytes.Buffer, label string, svc *zms.ServiceIdentity) {
	buf.WriteString("  \"" + label + "\": [\n")
	for idx, publicKey := range svc.PublicKeys {
		buf.WriteString("    {\n")
		buf.WriteString("      \"id\": \"" + publicKey.Id + "\",\n")
		buf.WriteString("      \"key\": \"" + publicKey.Key + "\"\n")
		buf.WriteString("    }")
		if idx != len(svc.PublicKeys)-1 {
			buf.WriteString(",")
		}
		buf.WriteString("\n")
	}
	buf.WriteString("  ]")
}

func getHttpTransport(socksProxy, keyFile, certFile, caCertFile *string, skipVerify bool) *http.Transport {
	tr := http.Transport{}
	if socksProxy != nil {
		dialer := &net.Dialer{}
		dialSocksProxy, err := proxy.SOCKS5("tcp", *socksProxy, nil, dialer)
		if err == nil {
			tr.Dial = dialSocksProxy.Dial
		}
	}
	if keyFile != nil || caCertFile != nil || skipVerify {
		config, err := GetTLSConfigFromFiles(certFile, keyFile, caCertFile)
		if err != nil {
			log.Fatalf("Unable to generate TLS config object, error: %v", err)
		}
		if skipVerify {
			config.InsecureSkipVerify = skipVerify
		}
		tr.Proxy = http.ProxyFromEnvironment
		tr.TLSClientConfig = config
	}
	return &tr
}

func GetTLSConfigFromFiles(certFile, keyFile, caCertFile *string) (*tls.Config, error) {
	var keyPem []byte
	var certPem []byte
	var caCertPem []byte
	var err error
	if keyFile != nil {
		keyPem, err = os.ReadFile(*keyFile)
		if err != nil {
			return nil, fmt.Errorf("Unable to read keyfile: %q, error: %v", *keyFile, err)
		}

		certPem, err = os.ReadFile(*certFile)
		if err != nil {
			return nil, fmt.Errorf("Unable to read certfile: %q, error: %v", *certFile, err)
		}
	}
	if caCertFile != nil {
		caCertPem, err = os.ReadFile(*caCertFile)
		if err != nil {
			return nil, fmt.Errorf("Unable to read ca certfile: %q, error: %v", *caCertFile, err)
		}
	}
	return GetTLSConfig(certPem, keyPem, caCertPem)
}

func GetTLSConfig(certPem, keyPem, caCertPem []byte) (*tls.Config, error) {
	config := &tls.Config{}
	if keyPem != nil {
		clientCert, err := tls.X509KeyPair(certPem, keyPem)
		if err != nil {
			return nil, fmt.Errorf("Unable to formulate clientCert from key and cert bytes, error: %v", err)
		}
		config.Certificates = make([]tls.Certificate, 1)
		config.Certificates[0] = clientCert
	}
	if caCertPem != nil {
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(caCertPem) {
			return nil, fmt.Errorf("Unable to append CA Certificate to pool")
		}
		config.RootCAs = certPool
	}
	return config, nil
}

func normalizeServerURL(url, suffix string) string {
	normURL := ""
	if strings.HasSuffix(url, suffix) {
		normURL = url[:len(url)-len(suffix)] + "/"
	} else if last := len(url) - 1; last >= 0 && url[last] == '/' {
		normURL = url
	} else {
		normURL = url + "/"
	}
	return normURL
}
