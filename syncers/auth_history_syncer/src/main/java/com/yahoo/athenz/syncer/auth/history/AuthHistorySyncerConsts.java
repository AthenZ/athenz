/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.syncer.auth.history;

public class AuthHistorySyncerConsts {
    private AuthHistorySyncerConsts() {
    }

    public static final String PROP_DYNAMODB_KEY_PATH            = "auth_history_syncer.dynamodb_key_path";
    public static final String PROP_DYNAMODB_CERT_PATH           = "auth_history_syncer.dynamodb_cert_path";
    public static final String PROP_DYNAMODB_DOMAIN              = "auth_history_syncer.dynamodb_aws_domain";
    public static final String PROP_DYNAMODB_ROLE                = "auth_history_syncer.dynamodb_aws_role";
    public static final String PROP_DYNAMODB_TRUSTSTORE          = "auth_history_syncer.dynamodb_trust_store_path";
    public static final String PROP_DYNAMODB_TRUSTSTORE_PASSWORD = "auth_history_syncer.dynamodb_trust_store_password";
    public static final String PROP_DYNAMODB_TRUSTSTORE_APPNAME  = "auth_history_syncer.dynamodb_trust_store_app_name";
    public static final String PROP_DYNAMODB_REGION              = "auth_history_syncer.dynamodb_region";
    public static final String PROP_DYNAMODB_ZTS_URL             = "auth_history_syncer.dynamodb_zts_url";
    public static final String PROP_DYNAMODB_EXTERNAL_ID         = "auth_history_syncer.dynamodb_external_id";
    public static final String PROP_DYNAMODB_MIN_EXPIRY_TIME     = "auth_history_syncer.dynamodb_min_expiry_time";
    public static final String PROP_DYNAMODB_MAX_EXPIRY_TIME     = "auth_history_syncer.dynamodb_max_expiry_time";

    public static final String PROP_CLOUDWATCH_ZMS_LOG_GROUP     = "auth_history_syncer.cloudwatch_zms_log_group";
    public static final String PROP_CLOUDWATCH_ZTS_LOG_GROUP     = "auth_history_syncer.cloudwatch_zts_log_group";
}
