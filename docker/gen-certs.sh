#!/bin/sh

# -------------------------------- ZMS --------------------------------

ZMS_PK_PATH='./zms/var/certs/zms_key.pem'
ZMS_CERT_CONFIG_PATH='./zms/var/certs/dev_x509_cert.cnf'
ZMS_CERT_OUT_PATH='./zms/var/certs/zms_cert.pem'
ZMS_KEYSTORE_PATH='./zms/var/certs/zms_keystore.pkcs12'

# create ZMS certificate
openssl req -new -extensions v3_req -config ${ZMS_CERT_CONFIG_PATH} -keyout ${ZMS_PK_PATH} -passout 'pass:athenz' | openssl req -x509 -extensions v3_req -days 365 -config ${ZMS_CERT_CONFIG_PATH} -key ${ZMS_PK_PATH} -passin 'pass:athenz' -in /dev/stdin -out ${ZMS_CERT_OUT_PATH}
# create ZMS keystore
openssl pkcs12 -export -noiter -out ${ZMS_KEYSTORE_PATH} -passout 'pass:athenz' -in ${ZMS_CERT_OUT_PATH} -inkey ${ZMS_PK_PATH} -passin 'pass:athenz'

# -------------------------------- ZTS --------------------------------

ZTS_PK_PATH='./zts/var/certs/zts_key.pem'
ZTS_CERT_CONFIG_PATH='./zts/var/certs/dev_x509_cert.cnf'
ZTS_CERT_OUT_PATH='./zts/var/certs/zts_cert.pem'
ZTS_KEYSTORE_PATH='./zts/var/certs/zts_keystore.pkcs12'
ZTS_TRUSTSTORE_PATH='./zts/var/certs/zts_truststore.jks'

# create ZTS certificate
openssl req -new -extensions v3_req -config ${ZTS_CERT_CONFIG_PATH} -keyout ${ZTS_PK_PATH} -passout 'pass:athenz' | openssl req -x509 -extensions v3_req -days 365 -config ${ZTS_CERT_CONFIG_PATH} -key ${ZTS_PK_PATH} -passin 'pass:athenz' -in /dev/stdin -out ${ZTS_CERT_OUT_PATH}
# create ZTS keystore
openssl pkcs12 -export -noiter -out ${ZTS_KEYSTORE_PATH} -passout 'pass:athenz' -in ${ZTS_CERT_OUT_PATH} -inkey ${ZTS_PK_PATH} -passin 'pass:athenz'
# create ZTS truststore
rm -f ${ZTS_TRUSTSTORE_PATH}
keytool -importcert -noprompt -alias zms -keystore ${ZTS_TRUSTSTORE_PATH} -file ${ZMS_CERT_OUT_PATH} -storepass 'athenz'

# prepare ZTS public key for signing
ZTS_SIGN_PRIVATE_KEY_PATH='./zts/var/keys/zts_private.pem'
ZTS_SIGN_PUBLIC_KEY_PATH='./zts/var/keys/zts_public.pem'
openssl rsa -in ${ZTS_SIGN_PRIVATE_KEY_PATH} -passin 'pass:athenz' -pubout > ${ZTS_SIGN_PUBLIC_KEY_PATH}

# -------------------------------- UI --------------------------------

UI_PK_PATH='./ui/keys/ui_key.pem'
UI_CERT_CONFIG_PATH='./ui/keys/dev_ui_x509_cert.cnf'
UI_CERT_OUT_PATH='./ui/keys/ui_cert.pem'

# create UI certificate
openssl req -new -extensions v3_req -config ${UI_CERT_CONFIG_PATH} -keyout ${UI_PK_PATH} -passout 'pass:athenz' | openssl req -x509 -extensions v3_req -days 365 -config ${UI_CERT_CONFIG_PATH} -key ${UI_PK_PATH} -passin 'pass:athenz' -in /dev/stdin -out ${UI_CERT_OUT_PATH}
