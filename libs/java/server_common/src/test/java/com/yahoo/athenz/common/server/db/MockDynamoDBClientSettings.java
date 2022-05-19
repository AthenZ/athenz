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

package com.yahoo.athenz.common.server.db;

import com.yahoo.athenz.auth.PrivateKeyStore;

public class MockDynamoDBClientSettings implements DynamoDBClientSettings {

    private String certPath;
    private String domainName;
    private String roleName;
    private String trustStore;
    private String trustStorePassword;
    private String ztsURL;
    private String region;
    private String keyPath;
    private String appName;

    public void setCertPath(String certPath) {
        this.certPath = certPath;
    }

    public void setDomainName(String domainName) {
        this.domainName = domainName;
    }

    public void setRoleName(String roleName) {
        this.roleName = roleName;
    }

    public void setTrustStore(String trustStore) {
        this.trustStore = trustStore;
    }

    public void setTrustStorePassword(String trustStorePassword) {
        this.trustStorePassword = trustStorePassword;
    }

    public void setZtsURL(String ztsURL) {
        this.ztsURL = ztsURL;
    }

    public void setRegion(String region) {
        this.region = region;
    }

    public void setKeyPath(String keyPath) {
        this.keyPath = keyPath;
    }

    public void setAppName(String appName) {
        this.appName = appName;
    }

    public void setExternalId(String externalId) {
        this.externalId = externalId;
    }

    public void setMinExpiryTimeStr(String minExpiryTimeStr) {
        this.minExpiryTimeStr = minExpiryTimeStr;
    }

    public void setMaxExpiryTimeStr(String maxExpiryTimeStr) {
        this.maxExpiryTimeStr = maxExpiryTimeStr;
    }

    public void setKeyStore(PrivateKeyStore keyStore) {
        this.keyStore = keyStore;
    }

    private String externalId;
    private String minExpiryTimeStr;
    private String maxExpiryTimeStr;
    private PrivateKeyStore keyStore;

    public MockDynamoDBClientSettings(String certPath, String domainName, String roleName, String trustStore, String trustStorePassword, String ztsURL, String region, String keyPath, String appName, String externalId, String minExpiryTimeStr, String maxExpiryTimeStr, PrivateKeyStore keyStore) {
        this.certPath = certPath;
        this.domainName = domainName;
        this.roleName = roleName;
        this.trustStore = trustStore;
        this.trustStorePassword = trustStorePassword;
        this.ztsURL = ztsURL;
        this.region = region;
        this.keyPath = keyPath;
        this.appName = appName;
        this.externalId = externalId;
        this.minExpiryTimeStr = minExpiryTimeStr;
        this.maxExpiryTimeStr = maxExpiryTimeStr;
        this.keyStore = keyStore;
    }

    public MockDynamoDBClientSettings() {
        this.certPath = "";
        this.domainName = "";
        this.roleName = "";
        this.trustStore = "";
        this.trustStorePassword = "";
        this.ztsURL = "";
        this.region = "";
        this.keyPath = "";
        this.appName = "";
        this.externalId = "";
        this.minExpiryTimeStr = "";
        this.maxExpiryTimeStr = "";
        this.keyStore = null;
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
