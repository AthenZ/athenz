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

package com.yahoo.athenz.zts.cert.impl;

import com.yahoo.athenz.auth.PrivateKeyStore;

import static com.yahoo.athenz.zts.ZTSConsts.*;

public class DynamoDBClientSettings {
    private String certPath;
    private String domainName;
    private String roleName;
    private String trustStore;
    private String trustStorePassword;
    private String ztsURL;
    private String region;
    private String keyPath;
    private String appName;
    private PrivateKeyStore keyStore;

    public DynamoDBClientSettings(PrivateKeyStore keyStore) {
        keyPath = System.getProperty(ZTS_PROP_DYNAMODB_KEY_PATH, "");
        certPath = System.getProperty(ZTS_PROP_DYNAMODB_CERT_PATH, "");
        domainName = System.getProperty(ZTS_PROP_DYNAMODB_DOMAIN, "");
        roleName = System.getProperty(ZTS_PROP_DYNAMODB_ROLE, "");
        trustStore = System.getProperty(ZTS_PROP_DYNAMODB_TRUSTSTORE, "");
        region = System.getProperty(ZTS_PROP_DYNAMODB_REGION, "");
        trustStorePassword = System.getProperty(ZTS_PROP_DYNAMODB_TRUSTSTORE_PASSWORD, "");
        appName = System.getProperty(ZTS_PROP_DYNAMODB_TRUSTSTORE_APPNAME, "");
        ztsURL = System.getProperty(ZTS_PROP_DYNAMODB_ZTS_URL, "");
        this.keyStore = keyStore;
    }

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

    public String getKeyPath() {
        return keyPath;
    }

    public String getCertPath() {
        return certPath;
    }

    public String getDomainName() {
        return domainName;
    }

    public String getRoleName() {
        return roleName;
    }

    public String getTrustStore() {
        return trustStore;
    }

    public String getZtsURL() {
        return ztsURL;
    }

    public String getRegion() {
        return region;
    }

    public String getTrustStorePassword() {
        if (keyStore == null) {
            return null;
        }

        return keyStore.getApplicationSecret(appName, trustStorePassword);
    }
}
