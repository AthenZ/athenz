/**
 * Copyright 2016 Yahoo Inc.
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
package com.yahoo.athenz.container;

/**
 * Contains constants shared by classes throughout the service.
 **/
public final class AthenzConsts {

    // System property names with defaults(where applicable)
    
    public static final String ATHENZ_PROP_ACCESS_LOG_RETAIN_DAYS = "athenz.access_log_retain_days";
    public static final String ATHENZ_PROP_ACCESS_LOG_NAME        = "athenz.access_log_name";
    public static final String ATHENZ_PROP_ACCESS_SLF4J_LOGGER    = "athenz.access_slf4j_logger";
    public static final String ATHENZ_PROP_ACCESS_LOG_DIR         = "athenz.access_log_dir";

    public static final String ATHENZ_PROP_KEYSTORE_PASSWORD      = "athenz.ssl_key_store_password";
    public static final String ATHENZ_PROP_KEYMANAGER_PASSWORD    = "athenz.ssl_key_manager_password";
    public static final String ATHENZ_PROP_TRUSTSTORE_PASSWORD    = "athenz.ssl_trust_store_password";
    public static final String ATHENZ_PROP_KEYSTORE_PATH          = "athenz.ssl_key_store";
    public static final String ATHENZ_PROP_KEYSTORE_TYPE          = "athenz.ssl_key_store_type";
    public static final String ATHENZ_PROP_TRUSTSTORE_PATH        = "athenz.ssl_trust_store";
    public static final String ATHENZ_PROP_TRUSTSTORE_TYPE        = "athenz.ssl_trust_store_type";
    public static final String ATHENZ_PROP_EXCLUDED_CIPHER_SUITES = "athenz.ssl_excluded_cipher_suites";
    public static final String ATHENZ_PROP_EXCLUDED_PROTOCOLS     = "athenz.ssl_excluded_protocols";
    public static final String ATHENZ_PROP_IDLE_TIMEOUT           = "athenz.http_idle_timeout";
    public static final String ATHENZ_PROP_SEND_SERVER_VERSION    = "athenz.http_send_server_version";
    public static final String ATHENZ_PROP_SEND_DATE_HEADER       = "athenz.http_send_date_header";
    public static final String ATHENZ_PROP_OUTPUT_BUFFER_SIZE     = "athenz.http_output_buffer_size";
    public static final String ATHENZ_PROP_REQUEST_HEADER_SIZE    = "athenz.http_reqeust_header_size";
    public static final String ATHENZ_PROP_RESPONSE_HEADER_SIZE   = "athenz.http_response_header_size";
    public static final String ATHENZ_PROP_LISTEN_HOST            = "athenz.listen_host";
    public static final String ATHENZ_PROP_KEEP_ALIVE             = "athenz.keep_alive";
    public static final String ATHENZ_PROP_MAX_THREADS            = "athenz.http_max_threads";
    public static final String ATHENZ_PROP_HOSTNAME               = "athenz.hostname";
    public static final String ATHENZ_PROP_HOME                   = "athenz.home";
    public static final String ATHENZ_PROP_DEBUG                  = "athens.debug";
    public static final String ATHENZ_PROP_HEALTH_CHECK_URI_LIST  = "athenz.health_check_uri_list";
    public static final String ATHENZ_PROP_HEALTH_CHECK_PATH      = "athenz.health_check_path";
    
    public static final String STR_DEF_ROOT     = "/home/athenz";
    public static final String STR_ENV_ROOT     = "ROOT";
    
    public static final String ATHENZ_PROP_HTTPS_PORT    = "athenz.tls_port";
    public static final String ATHENZ_PROP_HTTP_PORT     = "athenz.port";
    
    public static final int ATHENZ_HTTPS_PORT_DEFAULT = 0;
    public static final int ATHENZ_HTTP_PORT_DEFAULT  = 10080;
    public static final int ATHENZ_HTTP_MAX_THREADS   = 1024;
}

