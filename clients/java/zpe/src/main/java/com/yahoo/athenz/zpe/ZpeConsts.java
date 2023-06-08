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
package com.yahoo.athenz.zpe;

import com.yahoo.athenz.zts.DomainMetricType;

public final class ZpeConsts {

    public static final String ZPE_ACTION_MATCH_STRUCT   = "actionMatchStruct";
    public static final String ZPE_RESOURCE_MATCH_STRUCT = "resourceMatchStruct";
    public static final String ZPE_ROLE_MATCH_STRUCT     = "roleMatchStruct";
    
    public static final String ZPE_FIELD_ACTION      = "action";
    public static final String ZPE_FIELD_RESOURCE    = "resource";
    public static final String ZPE_FIELD_ROLE        = "role";
    public static final String ZPE_FIELD_EFFECT      = "effect";
    public static final String ZPE_FIELD_POLICY_NAME = "polname";
    
    public static final String ZPE_METRIC_SCOREBOARD_NAME       = "athenz_zpe_java_client";
    public static final String ZPE_METRIC_NAME                  = DomainMetricType.ACCESS_ALLOWED.toString();
    public static final String ZPE_METRIC_NAME_DENY             = DomainMetricType.ACCESS_ALLOWED_DENY.toString();
    public static final String ZPE_METRIC_NAME_DENY_NO_MATCH    = DomainMetricType.ACCESS_ALLOWED_DENY_NO_MATCH.toString();
    public static final String ZPE_METRIC_NAME_ALLOW            = DomainMetricType.ACCESS_ALLOWED_ALLOW.toString();
    public static final String ZPE_METRIC_NAME_ERROR            = DomainMetricType.ACCESS_ALLOWED_ERROR.toString();
    public static final String ZPE_METRIC_NAME_INVALID_TOKEN    = DomainMetricType.ACCESS_ALLOWED_TOKEN_INVALID.toString();
    public static final String ZPE_METRIC_NAME_EXPIRED_TOKEN    = DomainMetricType.ACCESS_Allowed_TOKEN_EXPIRED.toString();
    public static final String ZPE_METRIC_NAME_DOMAIN_NOT_FOUND = DomainMetricType.ACCESS_ALLOWED_DOMAIN_NOT_FOUND.toString();
    public static final String ZPE_METRIC_NAME_DOMAIN_MISMATCH  = DomainMetricType.ACCESS_ALLOWED_DOMAIN_MISMATCH.toString();
    public static final String ZPE_METRIC_NAME_DOMAIN_EXPIRED   = DomainMetricType.ACCESS_ALLOWED_DOMAIN_EXPIRED.toString();
    public static final String ZPE_METRIC_NAME_DOMAIN_EMPTY     = DomainMetricType.ACCESS_ALLOWED_DOMAIN_EMPTY.toString();
    public static final String ZPE_METRIC_NAME_CACHE_FAILURE    = DomainMetricType.ACCESS_ALLOWED_TOKEN_CACHE_FAILURE.toString();
    public static final String ZPE_METRIC_NAME_CACHE_NOT_FOUND  = DomainMetricType.ACCESS_ALLOWED_TOKEN_CACHE_NOT_FOUND.toString();
    public static final String ZPE_METRIC_NAME_CACHE_SUCCESS    = DomainMetricType.ACCESS_ALLOWED_TOKEN_CACHE_SUCCESS.toString();
    public static final String ZPE_METRIC_NAME_TOKEN_VALIDATE   = DomainMetricType.ACCESS_ALLOWED_TOKEN_VALIDATE.toString();
    public static final String ZPE_METRIC_LOAD_FILE_FAIL        = DomainMetricType.LOAD_FILE_FAIL.toString();
    public static final String ZPE_METRIC_LOAD_FILE_GOOD        = DomainMetricType.LOAD_FILE_GOOD.toString();
    public static final String ZPE_METRIC_LOAD_DOM_GOOD         = DomainMetricType.LOAD_DOMAIN_GOOD.toString();
    
    // properties
    public static final String ZPE_PROP_ATHENZ_CONF                  = "athenz.athenz_conf";
    public static final String ZPE_PROP_JWK_ATHENZ_CONF              = "athenz.jwk_athenz_conf";
  
    public static final String ZPE_PROP_STATS_ENABLED                = "athenz.zpe.enable_stats";
    public static final String ZPE_PROP_METRIC_CLASS                 = "athenz.zpe.metric_factory_class";
    public static final String ZPE_PROP_PUBLIC_KEY_CLASS             = "athenz.zpe.public_key_class";
    public static final String ZPE_PROP_CLIENT_IMPL                  = "athenz.zpe.updater_class";
    public static final String ZPE_PROP_MILLIS_BETWEEN_ZTS_CALLS     = "athenz.zpe.millis_between_zts_calls";
    public static final String ZPE_PROP_MILLIS_BETWEEN_RELOAD_CONFIG = "athenz.zpe.millis_between_reload_config";
    public static final String ZPE_PROP_TOKEN_OFFSET                 = "athenz.zpe.token_allowed_offset";
    public static final String ZPE_PROP_MAX_TOKEN_CACHE              = "athenz.zpe.max_token_cache_entries";
    public static final String ZPE_PROP_METRIC_WRITE_INTERVAL        = "athenz.zpe.metric_write_interval";
    public static final String ZPE_PROP_METRIC_FILE_PATH             = "athenz.zpe.metric_file_path";
    public static final String ZPE_PROP_MON_TIMEOUT                  = "athenz.zpe.monitor_timeout_secs";
    public static final String ZPE_PROP_MON_CLEANUP_TOKENS           = "athenz.zpe.cleanup_tokens_secs";
    public static final String ZPE_PROP_POLICY_DIR                   = "athenz.zpe.policy_dir";
    public static final String ZPE_PROP_SKIP_POLICY_DIR_CHECK        = "athenz.zpe.skip_policy_dir_check";
    public static final String ZPE_PROP_CHECK_POLICY_ZMS_SIGNATURE   = "athenz.zpe.check_policy_zms_signature";
    public static final String ZPE_PROP_X509_CA_ISSUERS              = "athenz.zpe.x509.ca.issuers";

}
