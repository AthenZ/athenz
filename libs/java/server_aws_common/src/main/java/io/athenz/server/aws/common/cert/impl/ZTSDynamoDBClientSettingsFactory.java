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

package io.athenz.server.aws.common.cert.impl;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.db.dynamodb.DynamoDBClientSettings;

public class ZTSDynamoDBClientSettingsFactory {

    public static final String ZTS_PROP_DYNAMODB_KEY_PATH                = "athenz.zts.dynamodb_key_path";
    public static final String ZTS_PROP_DYNAMODB_CERT_PATH               = "athenz.zts.dynamodb_cert_path";
    public static final String ZTS_PROP_DYNAMODB_DOMAIN                  = "athenz.zts.dynamodb_aws_domain";
    public static final String ZTS_PROP_DYNAMODB_ROLE                    = "athenz.zts.dynamodb_aws_role";
    public static final String ZTS_PROP_DYNAMODB_TRUSTSTORE              = "athenz.zts.dynamodb_trust_store_path";
    public static final String ZTS_PROP_DYNAMODB_TRUSTSTORE_PASSWORD     = "athenz.zts.dynamodb_trust_store_password";
    public static final String ZTS_PROP_DYNAMODB_TRUSTSTORE_APPNAME      = "athenz.zts.dynamodb_trust_store_app_name";
    public static final String ZTS_PROP_DYNAMODB_REGION                  = "athenz.zts.dynamodb_region";
    public static final String ZTS_PROP_DYNAMODB_ZTS_URL                 = "athenz.zts.dynamodb_zts_url";
    public static final String ZTS_PROP_DYNAMODB_EXTERNAL_ID             = "athenz.zts.dynamodb_external_id";
    public static final String ZTS_PROP_DYNAMODB_MIN_EXPIRY_TIME         = "athenz.zts.dynamodb_min_expiry_time";
    public static final String ZTS_PROP_DYNAMODB_MAX_EXPIRY_TIME         = "athenz.zts.dynamodb_max_expiry_time";
    public static final String ZTS_PROP_DYNAMODB_TRUSTSTORE_KEYGROUPNAME = "athenz.zts.dynamodb_trust_store_app_name";
    
    private final PrivateKeyStore keyStore;
    private final String keyPath;
    private final String certPath;
    private final String domainName;
    private final String roleName;
    private final String trustStore;
    private final String region;
    private final String trustStorePassword;
    private final String appName;
    private final String ztsURL;
    private final String externalId;
    private final Integer minExpiryTime;
    private final Integer maxExpiryTime;
    private final String keyGroupName;

    public ZTSDynamoDBClientSettingsFactory(PrivateKeyStore keyStore) {
        keyPath = System.getProperty(ZTS_PROP_DYNAMODB_KEY_PATH, "");
        certPath = System.getProperty(ZTS_PROP_DYNAMODB_CERT_PATH, "");
        domainName = System.getProperty(ZTS_PROP_DYNAMODB_DOMAIN, "");
        roleName = System.getProperty(ZTS_PROP_DYNAMODB_ROLE, "");
        trustStore = System.getProperty(ZTS_PROP_DYNAMODB_TRUSTSTORE, "");
        trustStorePassword = System.getProperty(ZTS_PROP_DYNAMODB_TRUSTSTORE_PASSWORD, "");
        appName = System.getProperty(ZTS_PROP_DYNAMODB_TRUSTSTORE_APPNAME, "");
        region = System.getProperty(ZTS_PROP_DYNAMODB_REGION, "");
        ztsURL = System.getProperty(ZTS_PROP_DYNAMODB_ZTS_URL, "");
        externalId = System.getProperty(ZTS_PROP_DYNAMODB_EXTERNAL_ID, null);
        String minExpiryTimeStr = System.getProperty(ZTS_PROP_DYNAMODB_MIN_EXPIRY_TIME, "");
        String maxExpiryTimeStr = System.getProperty(ZTS_PROP_DYNAMODB_MAX_EXPIRY_TIME, "");
        minExpiryTime = minExpiryTimeStr.isEmpty() ? null : Integer.parseInt(minExpiryTimeStr);
        maxExpiryTime = maxExpiryTimeStr.isEmpty() ? null : Integer.parseInt(maxExpiryTimeStr);
        keyGroupName = System.getProperty(ZTS_PROP_DYNAMODB_TRUSTSTORE_KEYGROUPNAME, "");

        this.keyStore = keyStore;
    }

    public DynamoDBClientSettings getDynamoDBClientSettings(boolean isAsyncClient) {
        return new DynamoDBClientSettings(certPath, domainName, roleName, trustStore, trustStorePassword,
                ztsURL, region, keyPath, appName, keyStore, externalId, minExpiryTime, maxExpiryTime,
                keyGroupName, isAsyncClient);
    }
}
