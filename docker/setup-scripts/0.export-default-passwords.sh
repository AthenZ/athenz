#!/bin/sh

### DB password
export ZMS_JDBC_PASSWORD=${ZMS_JDBC_PASSWORD:-mariadb}
export ZTS_CERT_JDBC_PASSWORD=${ZTS_CERT_JDBC_PASSWORD:-mariadb}
### SSL private key password
# export ZMS_PK_PASS=${ZMS_PK_PASS:-athenz}
# export ZTS_PK_PASS=${ZTS_PK_PASS:-athenz}
# export UI_PK_PASS=${UI_PK_PASS:-athenz}
### keystore password
export ZMS_SSL_KEYSTORE_PASS=${ZMS_SSL_KEYSTORE_PASS:-athenz}
export ZTS_SSL_KEYSTORE_PASS=${ZTS_SSL_KEYSTORE_PASS:-athenz}
export ZTS_ZTS_SSL_KEYSTORE_PASS=${ZTS_SSL_KEYSTORE_PASS}
### truststore password
export ZMS_SSL_TRUSTSTORE_PASS=${ZMS_SSL_TRUSTSTORE_PASS:-athenz}
export ZTS_SSL_TRUSTSTORE_PASS=${ZTS_SSL_TRUSTSTORE_PASS:-athenz}
export ZTS_ZTS_SSL_TRUSTSTORE_PASS=${ZTS_SSL_TRUSTSTORE_PASS}
