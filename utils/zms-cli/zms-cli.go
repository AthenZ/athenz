package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"reflect"
	"strings"
	"syscall"
	"time"

	"github.com/ardielle/ardielle-go/rdl"
	"gopkg.in/yaml.v2"

	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/net/proxy"

	"github.com/AthenZ/athenz/clients/go/zms"
	"github.com/AthenZ/athenz/libs/go/zmscli"
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
	return sDebug == "true"
}

func debugAuthNToken(identity string) string {
	i := strings.LastIndex(identity, ".")
	domain := identity[0:i]
	name := identity[i+1:]
	var buf bytes.Buffer
	buf.WriteString("v=U1;d=" + domain + ";n=" + name + ";s=fakesignature")
	return "v=U1;d=" + domain + ";n=" + name + ";s=fakesignature"
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
	// return false if duration exceeds maxAge
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

func getAuthNToken(identity, authorizedServices, zmsUrl string, tr *http.Transport) (string, error) {
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
	pass, err := terminal.ReadPassword(int(syscall.Stdin))
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
		URL:          zmsUrl,
		Transport:    tr,
		CredsHeaders: make(map[string]string),
		Timeout:      0,
	}

	zmsClient.AddCredentials(authHeader, authCreds)
	tok, err := zmsClient.GetUserToken(zms.SimpleName(user), authorizedServices, nil)
	if err != nil {
		return "", fmt.Errorf("cannot get user token for user: %s error: %v", user, err)
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
	buf.WriteString("usage: zms-cli [flags] command [params]\n")
	buf.WriteString(" flags:\n")
	buf.WriteString("   -a auditRef         Audit Reference Token if auditing is required for domain\n")
	buf.WriteString("   -b                  Bulk import/update mode. Do not read/display updated role/policy/service objects (default=false)\n")
	buf.WriteString("   -c cacert_file      CA Certificate file path\n")
	buf.WriteString("   -cert x509_cert     Athenz X.509 Certificate file for authentication\n")
	buf.WriteString("   -d domain           The domain used for every command that takes a domain argument\n")
	buf.WriteString("   -e skip_errors      Skip errors during import domain operation\n")
	buf.WriteString("   -f ntoken_file      Principal Authority NToken file used for authentication\n")
	buf.WriteString("   -i identity         User identity to authenticate as if NToken file is not specified\n")
	buf.WriteString("                       (default=" + defaultIdentity() + ")\n")
	buf.WriteString("   -k                  Disable peer verification of SSL certificates.\n")
	buf.WriteString("   -key x509_key       Athenz X.509 Key file for authentication\n")
	buf.WriteString("   -o output_format    Output format - json or yaml (default=yaml)\n")
	buf.WriteString("   -overwrite          Overwrites without checking for existence\n")
	buf.WriteString("   -r resource_owner   Resource Owner for the object being updated\n")
	buf.WriteString("   -s host:port        The SOCKS5 proxy to route requests through\n")
	buf.WriteString("   -v                  Verbose mode. Full resource names are included in output (default=false)\n")
	buf.WriteString("   -x                  For user token output, exclude the header name (default=false)\n")
	buf.WriteString("   -z zms_url          Base URL of the ZMS server to use\n")
	buf.WriteString("                       (default ZMS=" + defaultZmsURL() + ")\n")
	buf.WriteString("   -debug              Debug mode. Generates debug NTokens (default=false)\n")
	buf.WriteString("\n")
	buf.WriteString(" type 'zms-cli help' to see all available commands\n")
	buf.WriteString(" type 'zms-cli help [command]' for usage of the specified command\n")
	return buf.String()
}

func loadNtokenFromFile(fileName string) (string, error) {
	buf, err := os.ReadFile(fileName)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(buf)), nil
}

func printVersion() {
	if VERSION == "" {
		fmt.Println("zms-cli (development version)")
	} else {
		fmt.Println("zms-cli " + VERSION + " " + BUILD_DATE)
	}
}

func main() {
	pZMS := flag.String("z", defaultZmsURL(), "Base URL of the ZMS server to use")
	pIdentity := flag.String("i", defaultIdentity(), "the identity to authenticate as")
	pNtokenFile := flag.String("f", "", "ntoken file path")
	pCACert := flag.String("c", "", "CA Certificate file path")
	pVerbose := flag.Bool("v", false, "verbose mode. Full resource names are included in output")
	pBulkmode := flag.Bool("b", false, "bulk mode. Do not display updated role/policy/service in output")
	pProductIDSupport := flag.Bool("p", false, "Top Level Domain add operations require product ids")
	pAddSelf := flag.Bool("addself", true, "Add self to domain admin role")
	pDomain := flag.String("d", "", "The domain for the command to execute in. If not specified, only certain commands are available")
	pUserDomain := flag.String("u", "user", "User domain name as configured in Athenz systems")
	pHomeDomain := flag.String("h", "home", "Home domain name as configured in Athenz systems")
	pSocks := flag.String("s", defaultSocksProxy(), "The SOCKS5 proxy to route requests through, i.e. 127.0.0.1:1080")
	pSkipVerify := flag.Bool("k", false, "Disable peer verification of SSL certificates")
	pOutputFormat := flag.String("o", "manualYaml", "Output format - json or yaml")
	pOverwrite := flag.Bool("overwrite", false, "Overwrites without checking for existence")
	pDebug := flag.Bool("debug", defaultDebug(), "debug mode (for authentication, mainly)")
	pAuditRef := flag.String("a", "", "Audit Reference Token if auditing is enabled for the domain")
	pExcludeHeader := flag.Bool("x", false, "Exclude header in user-token output")
	pX509KeyFile := flag.String("key", "", "x.509 private key file for authentication")
	pX509CertFile := flag.String("cert", "", "x.509 certificate key file for authentication")
	pShowVersion := flag.Bool("version", false, "Show version")
	pSkipErrors := flag.Bool("e", true, "Skip all errors during import domain operation")
	pResourceOwner := flag.String("r", "", "Resource Owner for the object being updated")

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
		cli.HomeDomain = *pHomeDomain
		if len(args) == 2 {
			fmt.Println(cli.HelpSpecificCommand(false, args[1]))
		} else {
			fmt.Println(cli.HelpListCommand())
		}
		return
	} else if args[0] == "version" {
		printVersion()
		return
	}

	cli := zmscli.Zms{
		ZmsUrl:           *pZMS,
		Identity:         *pIdentity,
		Verbose:          *pVerbose,
		Bulkmode:         *pBulkmode,
		Interactive:      false,
		Domain:           *pDomain,
		AuditRef:         *pAuditRef,
		UserDomain:       *pUserDomain,
		HomeDomain:       *pHomeDomain,
		ProductIdSupport: *pProductIDSupport,
		Debug:            *pDebug,
		AddSelf:          *pAddSelf,
		OutputFormat:     *pOutputFormat,
		Overwrite:        *pOverwrite,
		SkipErrors:       *pSkipErrors,
		ResourceOwner:    *pResourceOwner,
	}

	if *pX509KeyFile != "" && *pX509CertFile != "" {
		err := zmscli.SetX509CertClient(&cli, *pX509KeyFile, *pX509CertFile, *pCACert, *pSocks, false, *pSkipVerify)
		if err != nil {
			log.Fatalf("Unable to set ZMS x.509 Client: %v\n", err)
		}
	} else {
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
		zmscli.SetClient(&cli, tr, &authHeader, &ntoken)

		if len(args) > 0 && args[0] == "get-user-token" {
			if len(args) == 2 {
				ntoken, err = getAuthNToken(identity, args[1], *pZMS, tr)
				if err != nil {
					log.Fatalf("Unable to get NToken for service: %s error: %v", args[1], err)
				}
			}
			if !(*pExcludeHeader) {
				fmt.Print(authHeader + ": ")
			}
			fmt.Println(ntoken)
			return
		}
	}

	msg, err := cli.EvalCommand(args)
	if err != nil {
		if reflect.ValueOf(err).Kind() != reflect.Struct {
			err = rdl.ResourceError{
				Code:    400,
				Message: err.Error(),
			}
		}
		switch cli.OutputFormat {
		case zmscli.JSONOutputFormat:
			jsonOutput, errJson := json.MarshalIndent(err, "", "    ")
			if errJson != nil {
				fmt.Println("failed to produce JSON output: ", errJson)
			}
			output := string(jsonOutput)
			fmt.Println(output)
		case zmscli.YAMLOutputFormat:
			yamlOutput, errYaml := yaml.Marshal(err)
			if errYaml != nil {
				fmt.Println("failed to produce YAML output: ", errYaml)
			}
			output := string(yamlOutput)
			fmt.Println(output)
		case zmscli.DefaultOutputFormat:
			yamlOutput, errYaml := yaml.Marshal(err)
			if errYaml != nil {
				fmt.Println("failed to produce YAML output: ", errYaml)
			}
			output := string(yamlOutput)
			fmt.Println(output)
		default:
			fmt.Println("***", err)
		}
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
			capem, err := os.ReadFile(*caCertFile)
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
