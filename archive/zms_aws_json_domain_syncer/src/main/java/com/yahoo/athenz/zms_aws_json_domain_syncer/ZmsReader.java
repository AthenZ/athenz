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
package com.yahoo.athenz.zms_aws_json_domain_syncer;

import com.oath.auth.KeyRefresher;
import com.oath.auth.Utils;
import com.yahoo.athenz.zms.SignedDomain;
import com.yahoo.athenz.zms.SignedDomains;
import com.yahoo.athenz.zms.ZMSClient;
import com.yahoo.athenz.zms.ZMSClientException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ZmsReader {

    private static final Logger LOGGER = LoggerFactory.getLogger(ZmsReader.class);

    private ZMSClient zmsClient = null;
    private final DomainValidator domainValidator = new DomainValidator();

    public ZmsReader() {
    }

    public ZmsReader(ZMSClient zmsClt) {
        this();
        zmsClient = zmsClt;
    }

    ZMSClient getClient() {

        if (zmsClient != null) {
            return zmsClient;
        }

        Config configInstance = Config.getInstance();
        String svcKeyFile = configInstance.getConfigParam(Config.SYNC_CFG_PARAM_ATH_SVC_KEYFILE);
        String svcCert = configInstance.getConfigParam(Config.SYNC_CFG_PARAM_ATH_SVC_CERT);
        String trustStorePath = configInstance.getConfigParam(Config.SYNC_CFG_PARAM_TRUSTSOURCE_PATH);
        String trustStorePassword = configInstance.getConfigParam(Config.SYNC_CFG_PARAM_TRUSTSOURCE_PASSWORD);
        String zmsUrl = configInstance.getConfigParam(Config.ZMS_CFG_PARAM_ZMS_URL);

        LOGGER.info("Client details - url: {}, service: {}", zmsUrl, "syncer");

        String zmsCltFactoryClass = configInstance.getConfigParam(Config.SYNC_CFG_PARAM_ZMSCLTFACT);

        try {
            if (zmsCltFactoryClass != null) {
                ZmsClientFactory zmsCltFactory = (ZmsClientFactory) Class.forName(zmsCltFactoryClass).newInstance();
                zmsClient = zmsCltFactory.createClient(zmsUrl, svcKeyFile, svcCert, trustStorePath, trustStorePassword);
                if (zmsClient != null) {
                    return zmsClient;
                }
            }

            // Create our SSL Context object based on our private key and
            // certificate and jdk truststore

            KeyRefresher keyRefresher = Utils.generateKeyRefresher(trustStorePath, trustStorePassword,
                    svcCert, svcKeyFile);
            // Default refresh period is every hour.
            keyRefresher.startup();
            // Can be adjusted to use other values in milliseconds.
            //keyRefresher.startup(900000);
            SSLContext sslContext = Utils.buildSSLContext(keyRefresher.getKeyManagerProxy(),
                    keyRefresher.getTrustManagerProxy());

            zmsClient = new ZMSClient(zmsUrl, sslContext);

        } catch (Exception ex) {
            LOGGER.error("Unable to process request", ex);
            return null;
        }

        return zmsClient;
    }

    public List<SignedDomain> getDomainList() {
        try {
            ZMSClient zmsClient = getClient();
            // we're going to ask for the full list of domains with their last modified
            // time but meta data only (no roles, policies, etc). We process the list
            // ourselves and if the modification times don't match, then we retrieve
            // the domain object and sync
            SignedDomains signedDomains = zmsClient.getSignedDomains(null, "true", null, true, null, null);
            LOGGER.info("getDomainList returned {} domains", signedDomains.getDomains().size());
            return signedDomains.getDomains();
        } catch (Exception exc) {
            LOGGER.error("ZMSReader:getDomainList: Error reading domain list from ZMS: " + exc.getMessage());
        }
        return null;
    }

    public SignedDomain getDomain(String domainName) {

        while (true) {
            try {
                return getZMSDomain(getClient(), domainName);
            } catch (ZMSClientException ex) {

                LOGGER.error("ZMSReader:getDomain: Error reading domain: {}, code {}, message {}",
                        domainName, ex.getCode(), ex.getMessage());

                if (ex.getCode() != ZMSClientException.TOO_MANY_REQUESTS) {
                    return null;
                }

                // we got rate limiting response so we're going to sleep
                // at least a second and retry our operation again

                try {
                    Thread.sleep(1000);
                } catch (InterruptedException ignored) {
                }

                LOGGER.info("Retrying to read domain: {}", domainName);
            }
        }
    }

    private SignedDomain getZMSDomain(ZMSClient zmsClient, final String domainName) {

        Map<String, List<String>> responseHeaders = new HashMap<>();
        SignedDomains signedDomains = zmsClient.getSignedDomains(domainName, null, null,
                false, null, responseHeaders);
        List<SignedDomain> sDomains = signedDomains.getDomains();
        if (sDomains == null || sDomains.isEmpty()) {
            return null;
        }

        SignedDomain sDomain = sDomains.get(0);
        if (domainValidator.validateSignedDomain(sDomain)) {
            return sDomain;
        }

        return null;
    }
}

