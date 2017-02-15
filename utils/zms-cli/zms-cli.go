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
	"github.com/yahoo/athenz/libs/go/zmscli"
)

//these get set by the build script via the LDFLAGS
var VERSION string
var BUILD_DATE string

func defaultZmsUrl() string {
	s := os.Getenv("ZMS")
	if s != "" {
		return s
	}
	return "https://localhost:4443/zms/v1"
}

func defaultIdentity() string {
	return "user." + os.Getenv("USER")
}

func defaultSocksProxy() string {
	return os.Getenv("SOCKS5_PROXY")
}

func defaultDebug() bool {
	sDebug := os.Getenv("ZMS_DEBUG")
	if sDebug == "true" {
		return true
	}
	return false
}

func debugAuthNToken(identity string) string {
	i := strings.LastIndex(identity, ".")
	domain := identity[0:i]
	name := identity[i+1:]
	var buf bytes.Buffer
	buf.WriteString("v=U1;d=" + domain + ";n=" + name + ";s=fakesignature")
	return "v=U1;d=" + domain + ";n=" + name + ";s=fakesignature"
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
	buf.WriteString("usage: zms-cli [flags] command [params]\n")
	buf.WriteString(" flags:\n")
	buf.WriteString("   -a auditRef         Audit Reference Token if auditing is required for domain\n")
	buf.WriteString("   -b                  Bulk import/update mode. Do not read/display updated role/policy/service objects (default=false)\n")
	buf.WriteString("   -c cacert_file      CA Certificate file path\n")
	buf.WriteString("   -d domain           The domain used for every command that takes a domain argument\n")
	buf.WriteString("   -f ntoken_file      Principal Authority NToken file used for authentication\n")
	buf.WriteString("   -i identity         User identity to authenticate as if NToken file is not specified\n")
	buf.WriteString("                       (default=" + defaultIdentity() + ")\n")
	buf.WriteString("   -k                  Disable peer verification of SSL certificates.\n")
	buf.WriteString("   -s host:port        The SOCKS5 proxy to route requests through\n")
	buf.WriteString("   -v                  Verbose mode. Full resource names are included in output (default=false)\n")
	buf.WriteString("   -z zms_url          Base URL of the ZMS server to use\n")
	buf.WriteString("                       (default ZMS=" + defaultZmsUrl() + ")\n")
	buf.WriteString("   -debug              Debug mode. Generates debug NTokens (default=false)\n")
	buf.WriteString("\n")
	buf.WriteString(" type 'zms-cli help' to see all available commands\n")
	buf.WriteString(" type 'zms-cli help [command]' for usage of the specified command\n")
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
	pIdentity := flag.String("i", defaultIdentity(), "the identity to authenticate as")
	pNtokenFile := flag.String("f", "", "ntoken file path")
	pCACert := flag.String("c", "", "CA Certificate file path")
	pVerbose := flag.Bool("v", false, "verbose mode. Full resource names are included in output")
	pBulkmode := flag.Bool("b", false, "bulk mode. Do not display updated role/policy/service in output")
	pProductIdSupport := flag.Bool("p", false, "Top Level Domain add operations require product ids")
	pDomain := flag.String("d", "", "The domain for the command to execute in. If not specified, only certain commands are available")
	pUserDomain := flag.String("u", "user", "User domain name as configured in Athenz systems")
	pSocks := flag.String("s", defaultSocksProxy(), "The SOCKS5 proxy to route requests through, i.e. 127.0.0.1:1080")
	pSkipVerify := flag.Bool("k", false, "Disable peer verification of SSL certificates")
	pDebug := flag.Bool("debug", defaultDebug(), "debug mode (for authentication, mainly)")
	pAuditRef := flag.String("a", "", "Audit Reference Token if auditing is enabled for the domain")
	flag.Usage = func() {
		fmt.Println(usage())
	}

	// first we need to parse our arguments based
	// on the flags we defined above

	flag.Parse()

	if *pZMS == "" {
		fmt.Println("No ZMS Url specified")
		return
	}

	// before processing our arguments verify that the zms
	// url is of expected format and return failure right
	// away otherwise the error message is somewhat
	// confusing when the hostname/port is valid but the
	// uri part is invalid resulting in 404 responses

	if !strings.HasSuffix(*pZMS, "/zms/v1") {
		fmt.Println("Invalid ZMS Url specified: " + *pZMS)
		fmt.Println("Valid ZMS Url has the following form: https://<zms-hostname>:<zms-port>/zms/v1")
		return
	}

	// now process our request

	args := flag.Args()
	if len(args) == 0 {
		fmt.Println(usage())
		return
	} else if args[0] == "help" {
		cli := zmscli.Zms{}
		cli.UserDomain = *pUserDomain
		if len(args) == 2 {
			fmt.Println(cli.HelpSpecificCommand(false, args[1]))
		} else {
			fmt.Println(cli.HelpListCommand())
		}
		return
	} else if args[0] == "version" {
		if VERSION == "" {
			fmt.Println("zms-cli (development version)")
		} else {
			fmt.Println("zms-cli " + VERSION + " " + BUILD_DATE)
		}
		return
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
		if *pDebug {
			ntoken = debugAuthNToken(identity)
		} else {
			ntoken, err = getAuthNToken(identity, "", *pZMS, tr)
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
	var authHeader = "Athenz-Principal-Auth"

	cli := zmscli.Zms{
		ZmsUrl:           *pZMS,
		Identity:         *pIdentity,
		Verbose:          *pVerbose,
		Bulkmode:         *pBulkmode,
		Interactive:      false,
		Domain:           *pDomain,
		AuditRef:         *pAuditRef,
		UserDomain:       *pUserDomain,
		ProductIdSupport: *pProductIdSupport,
		Debug:            *pDebug,
	}
	cli.SetClient(tr, &authHeader, &ntoken)

	if len(args) > 0 {
		switch args[0] {
		case "get-user-token":
			if len(args) == 2 {
				ntoken, err = getAuthNToken(identity, args[1], *pZMS, tr)
				if err != nil {
					log.Fatalf("Unable to get NToken for service: %s error: %v", args[1], err)
				}
			}
			fmt.Println("Athenz-Principal-Auth: " + ntoken)
			return
		case "repl":
			cli.Interactive = true
			cli.Repl()
			return
		default:
			break
		}
	}
	msg, err := cli.EvalCommand(args)
	if err != nil {
		fmt.Println("***", err)
		os.Exit(1)
	} else if msg != nil {
		fmt.Println(*msg)
		os.Exit(0)
	}
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
