/*
 *  Copyright The Athenz Authors
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

package com.yahoo.athenz.common.server.store.impl;

import com.oath.auth.KeyRefresher;
import com.oath.auth.KeyRefresherException;
import com.oath.auth.Utils;
import com.yahoo.athenz.common.server.store.ChangeLogStore;
import com.yahoo.athenz.zms.*;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.util.*;

import static com.yahoo.athenz.common.ServerCommonConsts.*;

public class ZMSFileMTLSChangeLogStore implements ChangeLogStore {

    private static final Logger LOGGER = LoggerFactory.getLogger(ZMSFileMTLSChangeLogStore.class);

    private ZMSClient zmsClient;
    private ZMSFileChangeLogStoreCommon changeLogStoreCommon;

    public ZMSFileMTLSChangeLogStore(String rootDirectory, final String keyPath, final String certPath,
                                     final String trustStorePath, final String trustStorePassword)
            throws InterruptedException, KeyRefresherException, IOException {
        this(rootDirectory, keyPath, certPath, trustStorePath, trustStorePassword.toCharArray());
    }

    public ZMSFileMTLSChangeLogStore(String rootDirectory, final String keyPath, final String certPath,
                                     final String trustStorePath, final char[] trustStorePassword)
            throws InterruptedException, KeyRefresherException, IOException {

        // check to see if we need to override the ZMS url from the config file

        final String overrideUrl = System.getProperty(ZTS_PROP_ZMS_URL_OVERRIDE);
        final String zmsUrl = (StringUtil.isEmpty(overrideUrl)) ? null : overrideUrl;

        // setup our mtls client first to make sure our settings are correct

        KeyRefresher keyRefresher = Utils.generateKeyRefresher(trustStorePath, trustStorePassword,
                certPath, keyPath);
        keyRefresher.startup();

        SSLContext sslContext = Utils.buildSSLContext(keyRefresher.getKeyManagerProxy(),
                keyRefresher.getTrustManagerProxy());

        zmsClient = new ZMSClient(zmsUrl, sslContext);

        // create our common logic object

        changeLogStoreCommon = new ZMSFileChangeLogStoreCommon(rootDirectory);
    }

    @Override
    public boolean supportsFullRefresh() {
        return changeLogStoreCommon.supportsFullRefresh();
    }

    @Override
    public SignedDomain getLocalSignedDomain(String domainName) {
        return changeLogStoreCommon.getLocalSignedDomain(domainName);
    }

    @Override
    public JWSDomain getLocalJWSDomain(String domainName) {
        return changeLogStoreCommon.getLocalJWSDomain(domainName);
    }

    @Override
    public SignedDomain getServerSignedDomain(String domainName) {

        try {
            return changeLogStoreCommon.getServerSignedDomain(zmsClient, domainName);
        } catch (ZMSClientException ex) {
            LOGGER.error("Error when fetching {} data from ZMS: {}", domainName, ex.getMessage());
            return null;
        }
    }

    @Override
    public JWSDomain getServerJWSDomain(String domainName) {

        try {
            return changeLogStoreCommon.getServerJWSDomain(zmsClient, domainName);
        } catch (ZMSClientException ex) {
            LOGGER.error("Error when fetching {} data from ZMS: {}", domainName, ex.getMessage());
            return null;
        }
    }

    @Override
    public void removeLocalDomain(String domainName) {
        changeLogStoreCommon.removeLocalDomain(domainName);
    }

    @Override
    public void saveLocalDomain(String domainName, SignedDomain signedDomain) {
        changeLogStoreCommon.saveLocalDomain(domainName, signedDomain);
    }

    @Override
    public void saveLocalDomain(String domainName, JWSDomain jwsDomain) {
        changeLogStoreCommon.saveLocalDomain(domainName, jwsDomain);
    }

    @Override
    public List<String> getLocalDomainList() {
        return changeLogStoreCommon.getLocalDomainList();
    }

    @Override
    public Map<String, DomainAttributes> getLocalDomainAttributeList() {
        return changeLogStoreCommon.getLocalDomainAttributeList();
    }

    @Override
    public Set<String> getServerDomainList() {

        Set<String> zmsDomainList;
        try {
            zmsDomainList = changeLogStoreCommon.getServerDomainList(zmsClient);
        } catch (ZMSClientException ex) {
            LOGGER.error("Unable to retrieve domain list from ZMS",  ex);
            return null;
        }

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Number of ZMS domains: {}", zmsDomainList.size());
        }

        return zmsDomainList;
    }

    @Override
    public SignedDomains getServerDomainModifiedList() {

        SignedDomains signedDomains = null;
        try {
            signedDomains = changeLogStoreCommon.getServerDomainModifiedList(zmsClient);

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Number of ZMS domains: {}", signedDomains == null ? 0 : signedDomains.getDomains().size());
            }
        } catch (ZMSClientException ex) {
            LOGGER.error("Unable to retrieve signed domain list from ZMS", ex);
        }

        return signedDomains;
    }

    @Override
    public void setLastModificationTimestamp(String newLastModTime) {
        changeLogStoreCommon.setLastModificationTimestamp(newLastModTime);
    }

    @Override
    public SignedDomains getUpdatedSignedDomains(StringBuilder lastModTimeBuffer) {

        try {
            return changeLogStoreCommon.getUpdatedSignedDomains(zmsClient, lastModTimeBuffer);
        } catch (ZMSClientException ex) {
            LOGGER.error("Error when refreshing data from ZMS: {}", ex.getMessage());
            return null;
        }
    }

    @Override
    public List<JWSDomain> getUpdatedJWSDomains(StringBuilder lastModTimeBuffer) {

        try {
            return changeLogStoreCommon.getUpdatedJWSDomains(zmsClient, lastModTimeBuffer);
        } catch (ZMSClientException ex) {
            LOGGER.error("Error when refreshing data from ZMS: {}", ex.getMessage());
            return null;
        }
    }

    void setZMSClient(ZMSClient client) {
        zmsClient = client;
    }

    void setChangeLogStoreCommon(ZMSFileChangeLogStoreCommon changeLogStoreCommon) {
        this.changeLogStoreCommon = changeLogStoreCommon;
    }

    @Override
    public void setRequestConditions(final boolean requestConditions) {
        changeLogStoreCommon.setRequestConditions(requestConditions);
    }
}
