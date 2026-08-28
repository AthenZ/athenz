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
package com.yahoo.athenz.crypki;

/**
 * Property names shared by Crypki backends. HTTP property names match
 * the existing ZTS {@code athenz.zts.certsign_*} settings so current
 * deployments keep working.
 */
public final class CrypkiConsts {

    public static final String PROP_CERTSIGN_BASE_URI            = "athenz.zts.certsign_base_uri";
    public static final String PROP_CERTSIGN_REQUEST_TIMEOUT     = "athenz.zts.certsign_request_timeout";
    public static final String PROP_CERTSIGN_CONNECT_TIMEOUT     = "athenz.zts.certsign_connect_timeout";
    public static final String PROP_CERTSIGN_RETRY_COUNT         = "athenz.zts.certsign_retry_count";
    public static final String PROP_CERTSIGN_MAX_EXPIRY_TIME     = "athenz.zts.certsign_max_expiry_time";
    public static final String PROP_CERTSIGN_PROVIDER_KEYS_FNAME = "athenz.zts.certsign_provider_keys_fname";
    public static final String PROP_CERTSIGN_RETRY_CONN_ONLY     = "athenz.zts.certsign_retry_conn_failures_only";
    public static final String PROP_CERTSIGN_CONN_MAX_PER_ROUTE  = "athenz.zts.certsign_conn_max_per_route";
    public static final String PROP_CERTSIGN_CONN_MAX_TOTAL      = "athenz.zts.certsign_conn_max_total";
    public static final String PROP_CERTSIGN_CONN_TIME_TO_LIVE   = "athenz.zts.certsign_conn_time_to_live";
    public static final String PROP_CERTSIGN_HANDSHAKE_TIMEOUT   = "athenz.zts.certsign_handshake_timeout";

    public static final String PROP_PRIVATE_KEY_STORE_FACTORY_CLASS = "athenz.zts.private_key_store_factory_class";
    public static final String DEFAULT_PRIVATE_KEY_STORE_FACTORY_CLASS =
            "com.yahoo.athenz.auth.impl.FilePrivateKeyStoreFactory";

    public static final String PROP_KEYSTORE_PATH        = "athenz.zts.ssl_key_store";
    public static final String PROP_KEYSTORE_TYPE        = "athenz.zts.ssl_key_store_type";
    public static final String PROP_KEYSTORE_PASSWORD    = "athenz.zts.ssl_key_store_password";
    public static final String PROP_TRUSTSTORE_PATH      = "athenz.zts.ssl_trust_store";
    public static final String PROP_TRUSTSTORE_TYPE      = "athenz.zts.ssl_trust_store_type";
    public static final String PROP_TRUSTSTORE_PASSWORD  = "athenz.zts.ssl_trust_store_password";

    public static final String PROP_KMS_KEY_ID           = "athenz.crypki.kms.key_id";
    public static final String PROP_KMS_CA_CERT_PATH     = "athenz.crypki.kms.ca_cert_path";
    public static final String PROP_KMS_SIGNING_ALGORITHM = "athenz.crypki.kms.signing_algorithm";
    public static final String PROP_HSM_MODULE_PATH      = "athenz.crypki.hsm.module_path";
    public static final String PROP_HSM_SLOT             = "athenz.crypki.hsm.slot";
    public static final String PROP_HSM_KEY_LABEL        = "athenz.crypki.hsm.key_label";
    public static final String PROP_HSM_PIN_PATH         = "athenz.crypki.hsm.pin_path";
    public static final String PROP_HSM_CA_CERT_PATH     = "athenz.crypki.hsm.ca_cert_path";
    public static final String DEFAULT_HSM_KEY_LABEL     = "athenz-crypki-ca";

    public static final String DEFAULT_KEY_ID = "x509-key";
    public static final String CERT_USAGE_CLIENT = "client";
    public static final String CERT_USAGE_CODE_SIGNING = "codeSigning";
    public static final String CERT_USAGE_TIMESTAMPING = "timestamping";

    public static final int DEFAULT_MAX_CERT_EXPIRY_TIME_MINS = 43200;

    private CrypkiConsts() {
    }
}
