#!/bin/bash

set -e

echo "running start.sh as `whoami`"

echo "---create athenz user---"
echo athenz:athenz::::/home/athenz:/bin/bash | sudo newusers

echo "---initializing zms---"
cd /opt/athenz/athenz-zms*
sed -ie 's/${USER}/athenz/g' /opt/athenz/athenz-zms*/conf/zms_server/zms.properties
if [ ! -f "./var/zms_server/keys/zms_private.pem" ]; then
    bin/setup_dev_zms.sh
fi

sudo -E bin/zms start
sleep 10

echo "---initializing ui---"
cd /opt/athenz/athenz-ui*/keys
if [ ! -f "./athenz.ui.pem" ]; then
    echo "---creating private/public key for ui---"
    openssl genrsa -out athenz.ui.pem 2048
    openssl rsa -in athenz.ui.pem -pubout > athenz.ui_pub.pem
    yes "" | openssl req -x509 -newkey rsa:2048 -keyout ui_key.pem -out ui_cert.pem -days 365 -passout pass:athenz
    cp /opt/athenz/athenz-zms*/var/zms_server/certs/zms_cert.pem .
fi

cd /opt/athenz/athenz-utils*/bin/linux
hostname=`hostname`

echo "---creating ntoken---"
ntoken=$(curl --silent -H "Authorization:Basic YXRoZW56OmF0aGVueg==" -k https://$hostname:4443/zms/v1/user/athenz/token | grep -o '\"token\":.*\"' | cut -d':' -f2 | sed 's/\"//'g )
echo $ntoken
printf "%s" "$ntoken" > ~/.ntoken
if [ ! -f ~/.ntoken ]; then
    echo "error: failed to find ntoken file"
    exit 1
fi

tokenExists=$(cat ~/.ntoken | grep 'n=athenz' | wc -l)
echo $tokenExists
if [ ! $tokenExists -eq "1" ]; then
    echo "error: failed to create ntoken"
    exit 1
fi

domainNotExist=`sudo ./zms-cli -i user.athenz -c /opt/athenz/athenz-ui*/keys/zms_cert.pem -z https://$hostname:4443/zms/v1 show-domain athenz | grep '404' | wc -l`
echo "athenz domain not found: $domainNotExist"
if [ $domainNotExist -eq "1" ]; then
    echo "---adding athenz domain with zms---"
    sudo ./zms-cli -i user.athenz -c /opt/athenz/athenz-ui*/keys/zms_cert.pem -z https://$hostname:4443/zms/v1 add-domain athenz
    
    echo "---registering ui with zms---"
    sudo ./zms-cli -c /opt/athenz/athenz-ui*/keys/zms_cert.pem -z https://$hostname:4443/zms/v1 -d athenz add-service ui 0 /opt/athenz/athenz-ui*/keys/athenz.ui_pub.pem
fi

echo "---starting athenz ui---"
cd /opt/athenz/athenz-ui*/
export ZMS_SERVER=$hostname
bin/athenz_ui start

echo "---initializing zts---"
cd /opt/athenz/athenz-zts*/var/zts_server/keys
if [ ! -f "./zts_private.pem" ]; then
    echo "---creating private/public key for zts---"
    openssl genrsa -out zts_private.pem 2048
    openssl rsa -in zts_private.pem -pubout > zts_public.pem
fi
cd /opt/athenz/athenz-zts*/var/zts_server/certs
if [ ! -f "./zts_key.pem" ]; then
    echo "---creating X509 Certificate for zts---"
    yes "" | openssl req -x509 -newkey rsa:2048 -keyout zts_key.pem -out zts_cert.pem -days 365 -passout pass:athenz
fi

if [ ! -f "./zts_keystore.pkcs12" ]; then
    echo "---creating keystore for zts---"
    openssl pkcs12 -export -out zts_keystore.pkcs12 -in zts_cert.pem -inkey zts_key.pem -passin pass:athenz -passout pass:athenz
fi

if [ ! -f "./zts_truststore.jks" ]; then
    echo "---creating truststore for zts from zms---"
    cp /opt/athenz/athenz-zms*/var/zms_server/certs/zms_cert.pem .
    keytool -importcert -noprompt -alias zms -keystore zts_truststore.jks -file zms_cert.pem -storepass athenz
fi

echo "---generate Athenz Configuration File---"
cd /opt/athenz/athenz-zts*
sudo /opt/athenz/athenz-utils*/bin/linux/athenz-conf -o ./conf/zts_server/athenz.conf -c /opt/athenz/athenz-zts*/var/zts_server/certs/zms_cert.pem -z https://$hostname:4443/ -t https://$hostname:8443/

cd /opt/athenz/athenz-utils*/bin/linux
serviceNotExist=$(sudo ./zms-cli -i user.athenz -c /opt/athenz/athenz-zts*/var/zts_server/certs/zms_cert.pem -z https://$hostname:4443/zms/v1 -d sys.auth show-service zts | grep '404' | wc -l)
echo $serviceNotExist
if [ $serviceNotExist -eq "1" ]; then
    echo "---registering zts service to zms---"
    sudo ./zms-cli -i user.athenz -c /opt/athenz/athenz-zts*/var/zts_server/certs/zms_cert.pem -z https://$hostname:4443/zms/v1 -d sys.auth add-service zts 0 /opt/athenz/athenz-zts*/var/zts_server/keys/zts_public.pem
fi

echo "---starting athenz zts---"
cd /opt/athenz/athenz-zts*/
sudo bin/zts start

