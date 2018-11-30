package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/yahoo/athenz/libs/go/zmssvctoken"
)

func usage() string {
	var buf bytes.Buffer
	buf.WriteString("usage: athenz-conf-aws -z <zms_url> -k <zms public key> [flags]\n")
	buf.WriteString(" flags:\n")
	buf.WriteString("   -z zms_url           Base URL of the ZMS server to use\n")
	buf.WriteString("   -k zms_public key    Public key of ZMS server to use\n")
	buf.WriteString("   -t zts_url           Base URL of the ZTS server to use\n")
	buf.WriteString("   -e zts_public key    Public key of zms server to use\n")
	buf.WriteString("   -o output_file       Output config filename (default=/opt/zts/conf/athenz.conf)\n")
	buf.WriteString("\n")
	return buf.String()
}

func main() {

	var ztsUrl, zmsUrl, ztsPublicKey, zmsPublicKey, outputFile string
	flag.StringVar(&zmsUrl, "z", "", "Base URL of the ZMS server to use")
	flag.StringVar(&ztsUrl, "t", "", "Base URL of the ZTS server to use")
	flag.StringVar(&zmsPublicKey, "k", "", "Public key file of ZMS server to use")
	flag.StringVar(&ztsPublicKey, "e", "", "Public key  file of ZTS server to use")
	flag.StringVar(&outputFile, "o", "/opt/zts/conf/athenz.conf", "The output athenz conf file")
	flag.Usage = func() {
		fmt.Println(usage())
	}

	flag.Parse()

	if zmsUrl == "" || zmsPublicKey == "" {
		fmt.Println(usage())
		log.Fatalf("zms url and key flags are mandatory")
	}

	if (ztsUrl == "" && ztsPublicKey != "") || (ztsUrl != "" && ztsPublicKey == "") {
		fmt.Println(usage())
		log.Fatalf("Both zts url and key should be passed")
	}

	byte, err := ioutil.ReadFile(zmsPublicKey)
	if err != nil {
		log.Fatalln(err)
	}
	zmsKey := new(zmssvctoken.YBase64).EncodeToString(byte)

	var ztsKey string
	if ztsPublicKey != "" {
		byte, err = ioutil.ReadFile(ztsPublicKey)
		if err != nil {
			log.Fatalln(err)
		}
		ztsKey = new(zmssvctoken.YBase64).EncodeToString(byte)
	}

	var buf bytes.Buffer
	buf.WriteString("{\n")
	buf.WriteString("\"zmsUrl\": \"" + zmsUrl + "\",\n")
	buf.WriteString("\"ztsUrl\": \"" + ztsUrl + "\",\n")
	buf.WriteString("\"ztsPublicKeys\": [\n")
	buf.WriteString("    {\n")
	buf.WriteString("      \"id\": \"0\",\n")
	buf.WriteString("      \"key\": \"" + ztsKey + "\"\n")
	buf.WriteString("    }")
	buf.WriteString("\n")
	buf.WriteString("], \n")
	buf.WriteString("\"zmsPublicKeys\": [\n")
	buf.WriteString("    {\n")
	buf.WriteString("      \"id\": \"0\",\n")
	buf.WriteString("      \"key\": \"" + zmsKey + "\"\n")
	buf.WriteString("    }")
	buf.WriteString("\n")
	buf.WriteString("]")
	buf.WriteString("\n")
	buf.WriteString("}\n")

	err = ioutil.WriteFile(outputFile, buf.Bytes(), 0644)
	if err != nil {
		log.Fatalf("Unable to write athenz.conf file, err: %v", err)
	}
	os.Exit(0)

}
