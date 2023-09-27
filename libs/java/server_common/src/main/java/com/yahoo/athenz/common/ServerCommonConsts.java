/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.yahoo.athenz.common;

public final class ServerCommonConsts {
    public static final String ADMIN_ROLE_NAME  = "admin";
    public static final String OBJECT_ROLE      = "role";
    public static final String OBJECT_GROUP     = "group";
    public static final String OBJECT_POLICY    = "policy";
    public static final String OBJECT_ENTITY    = "entity";
    public static final String USER_DOMAIN      = "user";

    public static final String USER_DOMAIN_PREFIX = "user.";

    // For S3ChangeLogStore
    public static final String ZTS_PROP_AWS_BUCKET_NAME = "athenz.zts.aws_bucket_name";
    public static final String ZTS_PROP_AWS_REGION_NAME = "athenz.zts.aws_region_name";

    // For ZMSFileChangeLogStore
    public static final String ZTS_PROP_ZMS_URL_OVERRIDE    = "athenz.zts.zms_url";
    public static final String ATHENZ_SYS_DOMAIN            = "sys.auth";
    public static final String ZTS_SERVICE                  = "zts";
    public static final String ZMS_SERVICE                  = "zms";
    public static final String PROP_USER_DOMAIN             = "athenz.user_domain";
    public static final String PROP_ATHENZ_CONF             = "athenz.athenz_conf";
    public static final String ZTS_PROP_FILE_NAME           = "athenz.zts.prop_file";
    public static final String PROP_DATA_STORE_SUBDIR = "athenz.server_common.data_store_subdir";

    public static final String REQUEST_PRINCIPAL      = "com.yahoo.athenz.auth.principal";
    public static final String REQUEST_AUTHORITY_ID   = "com.yahoo.athenz.auth.authority_id";
    public static final String REQUEST_X509_SERIAL    = "com.yahoo.athenz.auth.principal_x509_serial";
    public static final String REQUEST_URI_SKIP_QUERY = "com.yahoo.athenz.uri.skip_query";
    public static final String REQUEST_URI_ADDL_QUERY = "com.yahoo.athenz.uri.addl_query";
    public static final String REQUEST_SSL_SESSION    = "org.eclipse.jetty.servlet.request.ssl_session";

    public static final String METRIC_DEFAULT_FACTORY_CLASS = "com.yahoo.athenz.common.metrics.impl.NoOpMetricFactory";

    public static final String ACTION_LAUNCH     = "launch";
    public static final String RESOURCE_INSTANCE = "sys.auth:instance";

    // for tests
    public static final String ZTS_PROP_AWS_PUBLIC_CERT = "athenz.zts.aws_public_cert";
}
