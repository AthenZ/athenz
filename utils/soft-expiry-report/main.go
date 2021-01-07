package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/yahoo/athenz/clients/go/zms"
	"log"
	"os"
	"os/user"
	"strconv"
	"strings"
)

const ZMS_URL = "https://zms.athenz.ouroath.com:4443/zms/v1"


func main() {
	user, err := user.Current()

	pZmsEndPoint := flag.String("zms", ZMS_URL, "optional zms endpoint. default: "+ZMS_URL)
	pCertPath := flag.String("cert", "/Users/" + user.Username + "/.athenz/cert", "cert path")
	pKeyPath := flag.String("key", "/Users/" + user.Username + "/.athenz/key", "key path")
	pDomainNamesPath := flag.String("in", "domain-names", "domain names file path")
	pSoftExpiryPath := flag.String("out", "soft-expiry-report.csv", "soft expiry report file path")

	flag.Usage = func() {
		fmt.Println("usage: soft-expiry-report -key [path to key] -cert [path to cert] -zms [zms url]")
	}

	flag.Parse()

	zmsEndPoint := *pZmsEndPoint
	certPath := *pCertPath
	keyPath := *pKeyPath
	domainNamesPath := *pDomainNamesPath
	softExpiryPath := *pSoftExpiryPath

	log.Print(
		"Cert Path: " + certPath +
		"\nKey Path: " + keyPath +
		"\nZMS: " + zmsEndPoint +
		"\nDomain-Names Path: " + domainNamesPath +
		"\nSoft-Expiry-Report Path: " + softExpiryPath)

	domainsToCheck, err := readLines(domainNamesPath)
	if err != nil {
		log.Fatal("Failed to read domain-names input file, error: " + err.Error())
	}

	softExpiryReport, err := os.Create(softExpiryPath)
	if err != nil {
		log.Fatal("Failed to create soft-expiry-report, error: " + err.Error())
	}

	defer softExpiryReport.Close()

	// write csv header
	softExpiryReport.WriteString("MemberName," +
		"Role," +
		"SoftExpiry," +
		"EngineeringOwnerFirstName," +
		"EngineeringOwnerLastName," +
		"EngineeringOwnerShortID," +
		"EngineeringOwnerTitle," +
		"EngineeringOwnerWorkEmail," +
		"ProductOwnerFirstName," +
		"ProductOwnerLastName," +
		"ProductOwnerShortID," +
		"ProductOwnerTitle," +
		"ProductOwnerWorkEmail," +
		"VerticalKey," +
		"VerticalDesc," +
		"VerticalFamilyKey," +
		"VerticalFamilyDesc\n")

	products, err := GetProductsFromOpm(certPath, keyPath)
	if err != nil {
		log.Fatal("Failed to get products info from OPM, error: " + err.Error())
	}

	// Make a map productId -> product
	productsMap := make(map[int]Product)
	for _, product := range products {
		productsMap[product.ID] = product
	}

	zmsClient, err := GetZmsClient(certPath, keyPath, zmsEndPoint)
	if err != nil {
		log.Fatal("Failed to get zms client. Error: " + err.Error())
	}

	for _, domain := range domainsToCheck {

		overdueReview, err := zmsClient.GetOverdueReview(zms.DomainName(domain))
		if err != nil {
			log.Print("Failed to get overdue members (soft-expiry) for domain " + domain)
			continue
		}

		if overdueReview.Members == nil || len(overdueReview.Members) == 0 {
			log.Print("No overdue members in domain " + domain)
			continue
		}

		// Getting top level domain
		topLevelDomain := strings.Split(domain, ".")[0]
		domainResponse, err := zmsClient.GetDomain(zms.DomainName(topLevelDomain))
		if err != nil {
			log.Print("Failed getting domain meta for domain " + topLevelDomain)
			continue
		}

		productId := int(*domainResponse.YpmId)
		product := productsMap[productId]

		productInfo := product.EngineeringOwnerFirstName + "," +
			product.EngineeringOwnerLastName + "," +
			product.EngineeringOwnerShortID + "," +
			product.EngineeringOwnerTitle + "," +
			product.EngineeringOwnerWorkEmail + "," +
			product.ProductOwnerFirstName + "," +
			product.ProductOwnerLastName + "," +
			product.ProductOwnerShortID + "," +
			product.ProductOwnerTitle + "," +
			product.ProductOwnerWorkEmail + "," +
			strconv.Itoa(product.VerticalKey) + "," +
			product.VerticalDesc + "," +
				strconv.Itoa(product.VerticalFamilyKey) + "," +
			product.VerticalFamilyDesc

		for _, domainMember := range overdueReview.Members {
			for _, role := range domainMember.MemberRoles {
				overdueLine := string(domainMember.MemberName) + "," +
					string(role.RoleName) + "," +
					role.ReviewReminder.String() + "," +
					productInfo + "\n"
				softExpiryReport.WriteString(overdueLine)
			}
		}
	}
}

// readLines reads a whole file into memory
// and returns a slice of its lines.
func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}