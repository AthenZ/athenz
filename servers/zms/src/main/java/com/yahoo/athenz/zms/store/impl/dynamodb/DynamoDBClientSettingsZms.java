/*
 *  Copyright 2020 Verizon Media
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.zms.store.impl.dynamodb;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.db.DynamoDBClientSettings;

import static com.yahoo.athenz.zms.ZMSConsts.*;

public class DynamoDBClientSettingsZms implements DynamoDBClientSettings {
    private String certPath;
    private String domainName;
    private String roleName;
    private String trustStore;
    private String trustStorePassword;
    private String ztsURL;
    private String region;
    private String keyPath;
    private String appName;
    private String externalId;
    private String minExpiryTimeStr;
    private String maxExpiryTimeStr;
    private PrivateKeyStore keyStore;

    public DynamoDBClientSettingsZms(PrivateKeyStore keyStore) {
        keyPath = System.getProperty(ZMS_PROP_DYNAMODB_KEY_PATH, "");
        certPath = System.getProperty(ZMS_PROP_DYNAMODB_CERT_PATH, "");
        domainName = System.getProperty(ZMS_PROP_DYNAMODB_DOMAIN, "");
        roleName = System.getProperty(ZMS_PROP_DYNAMODB_ROLE, "");
        trustStore = System.getProperty(ZMS_PROP_DYNAMODB_TRUSTSTORE, "");
        region = System.getProperty(ZMS_PROP_DYNAMODB_REGION, "");
        trustStorePassword = System.getProperty(ZMS_PROP_DYNAMODB_TRUSTSTORE_PASSWORD, "");
        appName = System.getProperty(ZMS_PROP_DYNAMODB_TRUSTSTORE_APPNAME, "");
        ztsURL = System.getProperty(ZMS_PROP_DYNAMODB_ZTS_URL, "");
        externalId = System.getProperty(ZMS_PROP_DYNAMODB_EXTERNAL_ID);
        minExpiryTimeStr = System.getProperty(ZMS_PROP_DYNAMODB_MIN_EXPIRY_TIME, "");
        maxExpiryTimeStr = System.getProperty(ZMS_PROP_DYNAMODB_MAX_EXPIRY_TIME, "");

        this.keyStore = keyStore;
    }

    @Override
    public boolean areCredentialsProvided() {
        return (!keyPath.isEmpty() &&
                !certPath.isEmpty() &&
                !domainName.isEmpty() &&
                !roleName.isEmpty() &&
                !trustStore.isEmpty() &&
                !trustStorePassword.isEmpty() &&
                !ztsURL.isEmpty() &&
                !region.isEmpty() &&
                keyStore != null);
    }

    @Override
    public String getKeyPath() {
        return keyPath;
    }

    @Override
    public String getCertPath() {
        return certPath;
    }

    @Override
    public String getDomainName() {
        return domainName;
    }

    @Override
    public String getRoleName() {
        return roleName;
    }

    @Override
    public String getTrustStore() {
        return trustStore;
    }

    @Override
    public String getZtsURL() {
        return ztsURL;
    }

    @Override
    public String getRegion() {
        return region;
    }

    @Deprecated
    public String getTrustStorePassword() {
        return String.valueOf(getTrustStorePasswordChars());
    }

    @Override
    public char[] getTrustStorePasswordChars() {
        if (keyStore == null) {
            return null;
        }

        return keyStore.getSecret(appName, trustStorePassword);
    }

    @Override
    public String getExternalId() {
        return externalId;
    }

    @Override
    public String getMinExpiryTimeStr() {
        return minExpiryTimeStr;
    }

    @Override
    public String getMaxExpiryTimeStr() {
        return maxExpiryTimeStr;
    }


}
