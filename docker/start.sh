#!/bin/bash

set -e

echo "running start.sh as `whoami`"

echo "---create athenz user---"
echo athenz:athenz::::/home/athenz:/bin/bash | sudo newusers

cd /opt/athenz/athenz-zms*
if [ ! -f "./var/zms_server/keys/zms_private.pem" ]; then
    echo "---initializing zms---"
    sed -ie 's/${USER}/athenz/g' /opt/athenz/athenz-zms*/conf/zms_server/zms.properties
    bin/setup_dev_zms.sh
fi

hostname=`hostname`
public_hostname=`hostname`

sudo -E bin/zms start
set +e
for i in {1..10};
do
    status=$(curl -k -s -w %{http_code} --output /dev/null https://$hostname:4443/zms/v1/schema)
    if [ $status -eq "200" ]; then
        break;
    fi
    sleep 3
done
set -e

cd /opt/athenz/athenz-ui*/keys
if [ ! -f "./athenz.ui.pem" ]; then
    echo "---initializing ui---"
    echo "---creating private/public key for ui---"
    openssl genrsa -out athenz.ui.pem 2048
    openssl rsa -in athenz.ui.pem -pubout > athenz.ui_pub.pem
    echo "---copying zms X509 Certificate as ui X509 Certificate---"
    cp /opt/athenz/athenz-zms*/var/zms_server/certs/zms_key.pem ui_key.pem
    cp /opt/athenz/athenz-zms*/var/zms_server/certs/zms_cert.pem ui_cert.pem
    echo "---copying zms X509 Certificate for ui---"
    cp /opt/athenz/athenz-zms*/var/zms_server/certs/zms_cert.pem .
fi

cd /opt/athenz/athenz-utils*/bin/linux

echo "---creating ntoken---"
ntoken=$(curl --silent -H "Authorization:Basic YXRoZW56OmF0aGVueg==" -k https://$hostname:4443/zms/v1/user/athenz/token | grep -o '\"token\":.*\"' | cut -d':' -f2 | sed 's/\"//'g )
printf "%s" "$ntoken" > ~/.ntoken
if [ ! -f ~/.ntoken ]; then
    echo "error: failed to find ntoken file"
    exit 1
fi

tokenExists=$(cat ~/.ntoken | grep 'n=athenz' | wc -l)
if [ ! $tokenExists -eq "1" ]; then
    echo "error: failed to create ntoken"
    exit 1
fi

domainNotExist=`sudo ./zms-cli -i user.athenz -c /opt/athenz/athenz-ui*/keys/zms_cert.pem -z https://$hostname:4443/zms/v1 show-domain athenz | grep '404' | wc -l`
if [ $domainNotExist -eq "1" ]; then
    echo "---adding athenz domain with zms---"
    sudo ./zms-cli -i user.athenz -c /opt/athenz/athenz-ui*/keys/zms_cert.pem -z https://$hostname:4443/zms/v1 add-domain athenz

    echo "---registering ui with zms---"
    sudo ./zms-cli -c /opt/athenz/athenz-ui*/keys/zms_cert.pem -z https://$hostname:4443/zms/v1 -d athenz add-service ui 0 /opt/athenz/athenz-ui*/keys/athenz.ui_pub.pem
fi

cd /opt/athenz/athenz-ui*/
if [ ! -f "./config/athenz.conf" ]; then
    echo "---generate Athenz UI Configuration File---"
    sudo /opt/athenz/athenz-utils*/bin/linux/athenz-conf -o ./config/athenz.conf -c /opt/athenz/athenz-zms*/var/zms_server/certs/zms_cert.pem -z https://$hostname:4443/
fi

echo "---starting athenz ui---"
cd /opt/athenz/athenz-ui*/
export ZMS_SERVER=$public_hostname
export UI_SERVER=$public_hostname
bin/athenz_ui start

cd /opt/athenz/athenz-zts*/var/zts_server/keys
if [ ! -f "./zts_private.pem" ]; then
    echo "---initializing zts---"
    echo "---creating private/public key for zts---"
    openssl genrsa -out zts_private.pem 2048
    openssl rsa -in zts_private.pem -pubout > zts_public.pem
fi
cd /opt/athenz/athenz-zts*/var/zts_server/certs
if [ ! -f "./zts_key.pem" ]; then
    echo "---copying zms X509 Certificate as zts X509 Certificate---"
    cp /opt/athenz/athenz-zms*/var/zms_server/certs/zms_key.pem zts_key.pem
    cp /opt/athenz/athenz-zms*/var/zms_server/certs/zms_cert.pem zts_cert.pem
fi

if [ ! -f "./zts_keystore.pkcs12" ]; then
    echo "---creating keystore for zts---"
    openssl pkcs12 -export -out zts_keystore.pkcs12 -in zts_cert.pem -inkey zts_key.pem -passout pass:athenz
fi

if [ ! -f "./zts_truststore.jks" ]; then
    echo "---creating truststore for zts from zms---"
    cp /opt/athenz/athenz-zms*/var/zms_server/certs/zms_cert.pem .
    keytool -importcert -noprompt -alias zms -keystore zts_truststore.jks -file zms_cert.pem -storepass athenz
fi

cd /opt/athenz/athenz-zts*
if [ ! -f "./conf/zts_server/athenz.conf" ]; then
    echo "---generate Athenz Configuration File---"
    sudo /opt/athenz/athenz-utils*/bin/linux/athenz-conf -o ./conf/zts_server/athenz.conf -c /opt/athenz/athenz-zts*/var/zts_server/certs/zms_cert.pem -z https://$hostname:4443/ -t https://$hostname:8443/
fi

cd /opt/athenz/athenz-utils*/bin/linux
serviceNotExist=$(sudo ./zms-cli -i user.athenz -c /opt/athenz/athenz-zts*/var/zts_server/certs/zms_cert.pem -z https://$hostname:4443/zms/v1 -d sys.auth show-service zts | grep '404' | wc -l)
if [ $serviceNotExist -eq "1" ]; then
    echo "---registering zts service to zms---"
    sudo ./zms-cli -i user.athenz -c /opt/athenz/athenz-zts*/var/zts_server/certs/zms_cert.pem -z https://$hostname:4443/zms/v1 -d sys.auth add-service zts 0 /opt/athenz/athenz-zts*/var/zts_server/keys/zts_public.pem
fi

echo "---starting athenz zts---"
cd /opt/athenz/athenz-zts*/

sudo bin/zts start
