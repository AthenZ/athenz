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

package com.yahoo.athenz.db.dynamodb;

import com.yahoo.athenz.auth.PrivateKeyStore;

public class DynamoDBClientSettings {
    private final String certPath;
    private final String domainName;
    private final String roleName;
    private final String trustStore;
    private final String trustStorePassword;
    private final String ztsURL;
    private final String region;
    private final String keyPath;
    private final String appName;
    private final PrivateKeyStore keyStore;
    private final String externalId;
    private final Integer minExpiryTime;
    private final Integer maxExpiryTime;

    public DynamoDBClientSettings(String certPath,
                                  String domainName,
                                  String roleName,
                                  String trustStore,
                                  String trustStorePassword,
                                  String ztsURL,
                                  String region,
                                  String keyPath,
                                  String appName,
                                  PrivateKeyStore keyStore,
                                  String externalId,
                                  Integer minExpiryTime,
                                  Integer maxExpiryTime) {
        this.certPath = certPath;
        this.domainName = domainName;
        this.roleName = roleName;
        this.trustStore = trustStore;
        this.trustStorePassword = trustStorePassword;
        this.ztsURL = ztsURL;
        this.region = region;
        this.keyPath = keyPath;
        this.appName = appName;
        this.keyStore = keyStore;
        this.externalId = externalId;
        this.minExpiryTime = minExpiryTime;
        this.maxExpiryTime = maxExpiryTime;
    }

    public boolean areCredentialsProvided() {
        return (keyPath != null && !keyPath.isEmpty() &&
                certPath != null && !certPath.isEmpty() &&
                domainName != null && !domainName.isEmpty() &&
                roleName != null && !roleName.isEmpty() &&
                trustStore != null && !trustStore.isEmpty() &&
                trustStorePassword != null && !trustStorePassword.isEmpty() &&
                ztsURL != null && !ztsURL.isEmpty() &&
                region != null && !region.isEmpty() &&
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

    public String getExternalId() {
        return externalId;
    }

    public Integer getMinExpiryTime() {
        return minExpiryTime;
    }

    public Integer getMaxExpiryTime() {
        return maxExpiryTime;
    }

    @Deprecated
    public String getTrustStorePassword() {
        return String.valueOf(getTrustStorePasswordChars());
    }

    char[] getTrustStorePasswordChars() {
        if (keyStore == null) {
            return null;
        }

        return keyStore.getSecret(appName, trustStorePassword);
    }
}
