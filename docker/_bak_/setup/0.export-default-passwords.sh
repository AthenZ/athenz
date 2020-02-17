#!/bin/sh

### DB password
export ZMS_DB_ROOT_PASS="${ZMS_DB_ROOT_PASS:-mariadb}"
export ZMS_DB_ADMIN_PASS="${ZMS_DB_ADMIN_PASS:-mariadbmariadb}"
export ZTS_DB_ROOT_PASS="${ZTS_DB_ROOT_PASS:-mariadb}"
export ZTS_DB_ADMIN_PASS="${ZTS_DB_ADMIN_PASS:-mariadbmariadb}"
### SSL private key password
# export ZMS_PK_PASS=${ZMS_PK_PASS:-athenz}
# export ZTS_PK_PASS=${ZTS_PK_PASS:-athenz}
# export UI_PK_PASS=${UI_PK_PASS:-athenz}
### ZMS password
export ZMS_KEYSTORE_PASS=${ZMS_KEYSTORE_PASS:-athenz}
export ZMS_TRUSTSTORE_PASS=${ZMS_TRUSTSTORE_PASS:-athenz}
### ZTS password
export ZTS_KEYSTORE_PASS=${ZTS_KEYSTORE_PASS:-athenz}
export ZTS_TRUSTSTORE_PASS=${ZTS_TRUSTSTORE_PASS:-athenz}
export ZTS_SIGNER_KEYSTORE_PASS=${ZTS_KEYSTORE_PASS}
export ZTS_SIGNER_TRUSTSTORE_PASS=${ZTS_TRUSTSTORE_PASS}

echo "All required passwords are set in ENV."
