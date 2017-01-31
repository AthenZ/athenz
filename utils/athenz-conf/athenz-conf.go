package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/net/proxy"

	"github.com/yahoo/athenz/clients/go/zms"
)

//these get set by the build script via the LDFLAGS
var VERSION string
var BUILD_DATE string

func defaultZmsUrl() string {
	s := os.Getenv("ZMS")
	if s != "" {
		return s
	}
	return "https://localhost:4443/"
}

func defaultZtsUrl() string {
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

func isFreshFile(filename string, maxAge float64) bool {
	info, err := os.Stat(filename)
	if err != nil {
		return false
	}
	delta := time.Since(info.ModTime())
	duration := delta
	if duration.Minutes() > maxAge {
		return false
	}
	return true
}

func getCachedNToken() string {
	ntokenFile := os.Getenv("HOME") + "/.ntoken"
	if isFreshFile(ntokenFile, 45) {
		data, err := ioutil.ReadFile(ntokenFile)
		if err == nil {
			return string(data)
		} else {
			fmt.Printf("Couldn't read the file, error: %v\n", err)
		}
	}
	return ""
}

func getAuthNToken(identity, authorizedServices, zmsUrl string, tr *http.Transport) (string, error) {
	// our identity must be user
	if !strings.HasPrefix(identity, "user.") {
		return "", errors.New("Identity must start with user.")
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
		URL:         zmsUrl,
		Transport:   tr,
		CredsHeader: &authHeader,
		CredsToken:  &authCreds,
		Timeout:     0,
	}
	tok, err := zmsClient.GetUserToken(zms.SimpleName(user), authorizedServices)
	if err != nil {
		return "", fmt.Errorf("Cannot get user token for user: %s error: %v", user, err)
	}
	if tok.Token != "" {
		ntokenFile := os.Getenv("HOME") + "/.ntoken"
		data := []byte(tok.Token)
		ioutil.WriteFile(ntokenFile, data, 0600)
	}
	return string(tok.Token), nil
}

func usage() string {
	var buf bytes.Buffer
	buf.WriteString("usage: athenz-conf -z <zms_url> [flags]\n")
	buf.WriteString(" flags:\n")
	buf.WriteString("   -c cacert_file  CA Certificate file path\n")
	buf.WriteString("   -f ntoken_file  Principal Authority NToken file used for authentication\n")
	buf.WriteString("   -i identity     User identity to authenticate as if NToken file is not specified\n")
	buf.WriteString("                   (default=" + defaultIdentity() + ")\n")
	buf.WriteString("   -k              Disable peer verification of SSL certificates.\n")
	buf.WriteString("   -o              Output config filename (default=athenz.conf)\n")
	buf.WriteString("   -s host:port    The SOCKS5 proxy to route requests through\n")
	buf.WriteString("   -t zts_url      Base URL of the ZTS server to use\n")
	buf.WriteString("                   (default ZTS=" + defaultZtsUrl() + ")\n")
	buf.WriteString("   -z zms_url      Base URL of the ZS server to use\n")
	buf.WriteString("                   (default ZMS=" + defaultZmsUrl() + ")\n")
	buf.WriteString("\n")
	return buf.String()
}

func loadNtokenFromFile(fileName string) (string, error) {
	buf, err := ioutil.ReadFile(fileName)
	if err != nil {
		return "", err
	}
	return string(buf), nil
}

func main() {
	pZMS := flag.String("z", defaultZmsUrl(), "Base URL of the ZMS server to use")
	pZTS := flag.String("t", defaultZtsUrl(), "Base URL of the ZTS server to use")
	pIdentity := flag.String("i", defaultIdentity(), "the identity to authenticate as")
	pNtokenFile := flag.String("f", "", "ntoken file path")
	pCACert := flag.String("c", "", "CA Certificate file path")
	pOutputFile := flag.String("o", "athenz.conf", "config filename")
	pSocks := flag.String("s", defaultSocksProxy(), "The SOCKS5 proxy to route requests through, i.e. 127.0.0.1:1080")
	pSkipVerify := flag.Bool("k", false, "Disable peer verification of SSL certificates")
	flag.Usage = func() {
		fmt.Println(usage())
	}

	// first we need to parse our arguments based
	// on the flags we defined above

	flag.Parse()

	zmsConfUrl := normalizeServerUrl(*pZMS, "/zms/v1")
	ztsConfUrl := normalizeServerUrl(*pZTS, "/zts/v1")
	zmsUrl := zmsConfUrl + "zms/v1"

	if zmsUrl == "" {
		log.Fatalf("No ZMS Url specified")
	}

	// now process our request

	args := flag.Args()
	if len(args) == 1 {
		if args[0] == "help" {
			fmt.Println(usage())
			return
		} else if args[0] == "version" {
			if VERSION == "" {
				fmt.Println("athenz-conf (development version)")
			} else {
				fmt.Println("athenz-conf " + VERSION + " " + BUILD_DATE)
			}
			return
		}
	}

	identity := *pIdentity
	if strings.Index(identity, ".") < 0 {
		identity = "user." + identity
	}
	if *pSocks == "" {
		pSocks = nil
	}
	if *pCACert == "" {
		pCACert = nil
	}
	tr := getHttpTransport(pSocks, pCACert, *pSkipVerify)
	var ntoken string
	var err error
	if *pNtokenFile == "" {
		ntoken, err = getAuthNToken(identity, "", zmsUrl, tr)
		if err != nil {
			log.Fatalf("Unable to get NToken: %v", err)
		}
	} else {
		ntoken, err = loadNtokenFromFile(*pNtokenFile)
		if err != nil {
			log.Fatalf("Unable to load ntoken from file: '%s' err: %v", *pNtokenFile, err)
		}
	}
	zmsClient := zms.NewClient(zmsUrl, tr)
	zmsClient.AddCredentials("Athenz-Principal-Auth", ntoken)

	var buf bytes.Buffer
	buf.WriteString("{\n")
	buf.WriteString("  \"zmsUrl\": \"" + zmsConfUrl + "\",\n")
	if ztsConfUrl != "" {
		buf.WriteString("  \"ztsUrl\": \"" + ztsConfUrl + "\",\n")
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

	err = ioutil.WriteFile(*pOutputFile, buf.Bytes(), 0644)
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

func getHttpTransport(socksProxy, caCertFile *string, skipVerify bool) *http.Transport {
	tr := http.Transport{}
	if socksProxy != nil {
		dialer := &net.Dialer{}
		dialSocksProxy, err := proxy.SOCKS5("tcp", *socksProxy, nil, dialer)
		if err == nil {
			tr.Dial = dialSocksProxy.Dial
		}
	}
	if caCertFile != nil || skipVerify {
		config := &tls.Config{}
		if caCertFile != nil {
			capem, err := ioutil.ReadFile(*caCertFile)
			if err != nil {
				log.Fatalf("Unable to read CA Certificate file %s, error: %v", *caCertFile, err)
			}
			certPool := x509.NewCertPool()
			if !certPool.AppendCertsFromPEM(capem) {
				log.Fatalf("Unable to append CA Certificate to pool")
			}
			config.RootCAs = certPool
		}
		if skipVerify {
			config.InsecureSkipVerify = skipVerify
		}
		tr.TLSClientConfig = config
	}
	return &tr
}

func normalizeServerUrl(url, suffix string) string {
	normUrl := ""
	if strings.HasSuffix(url, suffix) {
		normUrl = url[:len(url)-len(suffix)] + "/"
	} else if last := len(url) - 1; last >= 0 && url[last] == '/' {
		normUrl = url
	} else {
		normUrl = url + "/"
	}
	return normUrl
}
