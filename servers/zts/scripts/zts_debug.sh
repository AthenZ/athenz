#!/bin/bash

# setup ZTS settings for debug run

export ZTS_OPTS="${ZTS_OPTS} -Dathenz.zts.home=./"
export ZTS_OPTS="${ZTS_OPTS} -Dathenz.zts.zms_url=http://localhost:4080/"
export ZTS_OPTS="${ZTS_OPTS} -Dathenz.zts.authority_classes=com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority,com.yahoo.athenz.common.server.debug.DebugUserAuthority,com.yahoo.athenz.common.server.debug.DebugRoleAuthority,com.yahoo.athenz.common.server.debug.DebugKerberosAuthority"
export ZTS_OPTS="${ZTS_OPTS} -Dathenz.zts.port=8080"
export ZTS_OPTS="${ZTS_OPTS} -Dathenz.auth.private_key_store.private_key=src/test/resources/zts_private.pem"
export ZTS_OPTS="${ZTS_OPTS} -Dathenz.zts.private_key_store_factory_class=com.yahoo.athenz.auth.impl.FilePrivateKeyStoreFactory"
export ZTS_OPTS="${ZTS_OPTS} -Dathenz.auth.private_key_store.private_key_id=0"
export ZTS_OPTS="${ZTS_OPTS} -Dathenz.zts.access_log_dir=./zts_logs"
export ZTS_OPTS="${ZTS_OPTS} -Dathenz.zts.enable_stats=false"
export ZTS_OPTS="${ZTS_OPTS} -Dathenz.zts.zms_domain_update_timeout=30"
export ZTS_OPTS="${ZTS_OPTS} -Dathenz.zts.zms_domain_delete_timeout=60"
export ZTS_OPTS="${ZTS_OPTS} -Dathenz.zts.cert_signer_factory_class=com.yahoo.athenz.zts.cert.impl.SelfCertSignerFactory"
export ZTS_OPTS="${ZTS_OPTS} -Dathenz.zts.self_signer_private_key_fname=src/test/resources/private_encrypted.key"
export ZTS_OPTS="${ZTS_OPTS} -Dathenz.zts.self_signer_private_key_password=athenz"
export ZTS_OPTS="${ZTS_OPTS} -Dlogback.configurationFile=src/test/resources/logback.xml"
export ZTS_OPTS="${ZTS_OPTS} -Dathenz.athenz_conf=src/test/resources/athenz.conf"

if [ "$1" == "-ssl" ]; then
    export ZTS_OPTS="${ZTS_OPTS} -Dathenz.zts.tls_port=8443"
    export ZTS_OPTS="${ZTS_OPTS} -Dathenz.zts.ssl_key_store_password=password"
    export ZTS_OPTS="${ZTS_OPTS} -Dathenz.zts.ssl_key_store=file://$HOME/.keystore"
    export ZTS_OPTS="${ZTS_OPTS} -Dathenz.zts.ssl_key_store_type=PKCS12"
fi

# make sure the access log directory exists

mkdir -p ./zts_logs

mvn exec:java -Dexec.mainClass="com.yahoo.athenz.zts.ZTS" ${ZTS_OPTS} -Dexec.classpathScope="test"
