#!/bin/bash

# setup ZMS settings for debug run

export ZMS_OPTS="${ZMS_OPTS} -Dlogback.configurationFile=src/test/resources/logback.xml"
export ZMS_OPTS="${ZMS_OPTS} -Dathenz.zms.domain_admin=user.$USER,user.zms_test_admin,user.user_admin"
export ZMS_OPTS="${ZMS_OPTS} -Dathenz.zms.authority_classes=com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority,com.yahoo.athenz.common.server.debug.DebugUserAuthority,com.yahoo.athenz.common.server.debug.DebugRoleAuthority,com.yahoo.athenz.common.server.debug.DebugKerberosAuthority"
export ZMS_OPTS="${ZMS_OPTS} -Dathenz.zms.home=./"
export ZMS_OPTS="${ZMS_OPTS} -Dathenz.zms.port=4080"
export ZMS_OPTS="${ZMS_OPTS} -Dathenz.zms.private_key_store_factory_class=com.yahoo.athenz.auth.impl.FilePrivateKeyStoreFactory"
export ZMS_OPTS="${ZMS_OPTS} -Dathenz.zms.privatekey=src/test/resources/zms_private.pem"
export ZMS_OPTS="${ZMS_OPTS} -Dathenz.zms.privatekey.version=0"
export ZMS_OPTS="${ZMS_OPTS} -Dathenz.zms.access_log_dir=./zms_logs"
export ZMS_OPTS="${ZMS_OPTS} -Dathenz.zms.enable_stats=false"
export ZMS_OPTS="${ZMS_OPTS} -Dathenz.zms.virtual_domain_support=true"
export ZMS_OPTS="${ZMS_OPTS} -Dathenz.zms.virtual_domain_limit=0"
export ZMS_OPTS="${ZMS_OPTS} -Dathenz.zms.solution_templates_fname=src/test/resources/solution_templates.json"
export ZMS_OPTS="${ZMS_OPTS} -Dathenz.zms.authz_service_fname=src/test/resources/authorized_services.json"

if [ "$1" == "-ssl" ]; then 
    export ZMS_OPTS="${ZMS_OPTS} -Dathenz.zms.tls_port=4443"
    export ZMS_OPTS="${ZMS_OPTS} -Dathenz.zms.ssl_key_store_password=password"
    export ZMS_OPTS="${ZMS_OPTS} -Dathenz.zms.ssl_key_store=file://$HOME/.keystore"
    export ZMS_OPTS="${ZMS_OPTS} -Dathenz.zms.ssl_key_store_type=PKCS12"
fi


# make sure the access log directory exits

mkdir -p ./zms_logs

mvn exec:java -Dexec.mainClass="com.yahoo.athenz.zms.ZMS" ${ZMS_OPTS}

# Copyright 2016 Yahoo Inc.
# Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.
