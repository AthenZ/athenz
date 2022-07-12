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

package com.yahoo.athenz.zms_aws_domain_syncer;

import com.oath.auth.KeyRefresher;
import com.oath.auth.Utils;
import com.yahoo.athenz.zms.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ZmsReader {

    private static final Logger LOGGER = LoggerFactory.getLogger(ZmsReader.class);

    private final ZMSClient zmsClient;
    private final DomainValidator domainValidator;

    public ZmsReader() throws Exception {
        this.domainValidator = new DomainValidator();
        this.zmsClient = initializeZmsClient();
    }

    public ZmsReader(ZMSClient zmsClient, DomainValidator domainValidator) {
        this.domainValidator = domainValidator;
        this.zmsClient = zmsClient;
    }

    ZMSClient initializeZmsClient() throws Exception {

        Config configInstance = Config.getInstance();
        String svcKeyFile = configInstance.getConfigParam(Config.SYNC_CFG_PARAM_ATHENZ_SVC_KEYFILE);
        String svcCert = configInstance.getConfigParam(Config.SYNC_CFG_PARAM_ATHENZ_SVC_CERT);
        String trustStorePath = configInstance.getConfigParam(Config.SYNC_CFG_PARAM_TRUST_STORE_PATH);
        String trustStorePassword = configInstance.getConfigParam(Config.SYNC_CFG_PARAM_TRUST_STORE_PASSWORD);
        String zmsUrl = configInstance.getConfigParam(Config.ZMS_CFG_PARAM_ZMS_URL);

        LOGGER.info("client details - url: {}, service: syncer", zmsUrl);

        // Create our SSL Context object based on our private key and
        // certificate and jdk truststore

        KeyRefresher keyRefresher = Utils.generateKeyRefresher(trustStorePath, trustStorePassword,
                svcCert, svcKeyFile);
        // Default refresh period is every hour.
        keyRefresher.startup();
        SSLContext sslContext = Utils.buildSSLContext(keyRefresher.getKeyManagerProxy(),
                keyRefresher.getTrustManagerProxy());

        return new ZMSClient(zmsUrl, sslContext);
    }

    public List<SignedDomain> getDomainList() {
        try {
            // we're going to ask for the full list of domains with their last modified
            // time but metadata only (no roles, policies, etc.). We process the list
            // ourselves and if the modification times don't match, then we retrieve
            // the domain object and sync
            SignedDomains signedDomains = zmsClient.getSignedDomains(null, "true", null, true, null, null);
            LOGGER.info("getDomainList returned {} domains", signedDomains.getDomains().size());
            return signedDomains.getDomains();
        } catch (Exception ex) {
            LOGGER.error("error reading domain list from ZMS: {}", ex.getMessage());
        }
        return null;
    }

    public JWSDomain getDomain(String domainName) {

        while (true) {
            try {
                return getZMSDomain(domainName);
            } catch (ZMSClientException ex) {

                LOGGER.error("error reading domain: {}, code {}, message {}",
                        domainName, ex.getCode(), ex.getMessage());

                if (ex.getCode() != ZMSClientException.TOO_MANY_REQUESTS) {
                    return null;
                }

                // we got rate limiting response, so we're going to sleep
                // at least a second and retry our operation again

                try {
                    Thread.sleep(1000);
                } catch (InterruptedException ignored) {
                }

                LOGGER.info("retrying to read domain: {}", domainName);
            }
        }
    }

    private JWSDomain getZMSDomain(final String domainName) {

        Map<String, List<String>> responseHeaders = new HashMap<>();
        JWSDomain jwsDomain = zmsClient.getJWSDomain(domainName, null, responseHeaders);
        if (jwsDomain != null && !domainValidator.validateJWSDomain(jwsDomain)) {
            jwsDomain = null;
        }
        return jwsDomain;
    }

    public DomainData getDomainData(JWSDomain jwsDomain) {
        return domainValidator.getDomainData(jwsDomain);
    }
}
