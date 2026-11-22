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
package com.yahoo.athenz.zts;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.ServerCommonConsts;
import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.common.server.identity.SelfIdentityStore;
import com.yahoo.athenz.common.server.util.ConfigProperties;
import org.bouncycastle.asn1.x509.GeneralName;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Issues a client certificate for the server's own identity (sys.auth.zts)
 * with the server's cert signer and hands the key and certificate to the
 * configured store. The request follows the server's service certificate
 * policy. The certificate is refreshed at the configured interval.
 */
public class SelfIdentityManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(SelfIdentityManager.class);

    static final String DOMAIN_NAME  = ServerCommonConsts.ATHENZ_SYS_DOMAIN;
    static final String SERVICE_NAME = ServerCommonConsts.ZTS_SERVICE;
    static final String COMMON_NAME  = DOMAIN_NAME + "." + SERVICE_NAME;

    // same defaults as the spiffe trust domain uri validator

    static final String DEFAULT_SPIFFE_TRUST_DOMAIN = "athenz.io";
    static final String SPIFFE_NAMESPACE = "default";

    static final String SPIFFE_URI_FORMAT_TRUST_DOMAIN = "trust_domain";
    static final String SPIFFE_URI_FORMAT_BASIC = "basic";
    static final String SPIFFE_URI_FORMAT_NONE = "none";

    static final String KEY_ALGORITHM_RSA = "RSA";
    static final String KEY_ALGORITHM_EC  = "EC";
    static final int RSA_KEY_SIZE = 2048;
    static final String EC_CURVE = "prime256v1";

    static final int DEFAULT_REFRESH_INTERVAL_MINS = 1440;
    static final long RETRY_INTERVAL_MILLIS = TimeUnit.MINUTES.toMillis(5);

    /**
     * Generates a service certificate according to the server's
     * service certificate policy.
     */
    @FunctionalInterface
    interface CertIssuer {
        Identity issue(String domainName, String serviceName, String csr, int expiryMins)
                throws ServerResourceException;
    }

    private final SelfIdentityStore store;
    private final CertIssuer certIssuer;
    final int certExpiryMins;
    final long refreshIntervalMillis;
    final String keyAlgorithm;
    final String spiffeUri;
    ScheduledExecutorService scheduler;

    SelfIdentityManager(SelfIdentityStore store, CertIssuer certIssuer) throws ServerResourceException {

        this.store = store;
        this.certIssuer = certIssuer;

        // invalid and non-positive values fall back to 0 (server default)

        certExpiryMins = ConfigProperties.retrieveConfigSetting(ZTSConsts.ZTS_PROP_SELF_IDENTITY_CERT_EXPIRY_MINS, 0);
        refreshIntervalMillis = TimeUnit.MINUTES.toMillis(ConfigProperties.retrieveConfigSetting(
                ZTSConsts.ZTS_PROP_SELF_IDENTITY_REFRESH_INTERVAL_MINS, DEFAULT_REFRESH_INTERVAL_MINS));

        keyAlgorithm = System.getProperty(ZTSConsts.ZTS_PROP_SELF_IDENTITY_KEY_ALGORITHM, KEY_ALGORITHM_RSA)
                .toUpperCase();
        if (!KEY_ALGORITHM_RSA.equals(keyAlgorithm) && !KEY_ALGORITHM_EC.equals(keyAlgorithm)) {
            throw error("unsupported " + ZTSConsts.ZTS_PROP_SELF_IDENTITY_KEY_ALGORITHM + " value: " + keyAlgorithm);
        }

        spiffeUri = getSpiffeUri(System.getProperty(ZTSConsts.ZTS_PROP_SELF_IDENTITY_SPIFFE_URI_FORMAT,
                SPIFFE_URI_FORMAT_TRUST_DOMAIN).toLowerCase());
    }

    String getSpiffeUri(final String format) throws ServerResourceException {

        // use the same formats as the spiffe trust domain and basic uri validators:
        //   trust_domain: spiffe://<trust-domain>/ns/<namespace>/sa/<domain>.<service>
        //   basic:        spiffe://<domain>/sa/<service>
        //   none:         no spiffe uri in the certificate

        switch (format) {
            case SPIFFE_URI_FORMAT_TRUST_DOMAIN:
                final String trustDomain = System.getProperty(ZTSConsts.ZTS_PROP_SPIFFE_TRUST_DOMAIN,
                        DEFAULT_SPIFFE_TRUST_DOMAIN);
                return "spiffe://" + trustDomain + "/ns/" + SPIFFE_NAMESPACE + "/sa/" + COMMON_NAME;
            case SPIFFE_URI_FORMAT_BASIC:
                return "spiffe://" + DOMAIN_NAME + "/sa/" + SERVICE_NAME;
            case SPIFFE_URI_FORMAT_NONE:
                return null;
            default:
                throw error("unsupported " + ZTSConsts.ZTS_PROP_SELF_IDENTITY_SPIFFE_URI_FORMAT + " value: " + format);
        }
    }

    /**
     * Issue and store the initial identity and schedule its refresh.
     * @throws ServerResourceException if the initial identity cannot be issued or stored
     */
    void start() throws ServerResourceException {

        refreshIdentity();

        scheduler = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "self-identity-refresh");
            thread.setDaemon(true);
            return thread;
        });
        scheduleRefresh(refreshIntervalMillis);
    }

    void close() {
        if (scheduler != null) {
            scheduler.shutdownNow();
        }
    }

    X509Certificate refreshIdentity() throws ServerResourceException {

        // the crypto helpers and the store may report failures with
        // runtime exceptions, so we convert them into our checked type

        try {
            return issueIdentity();
        } catch (ServerResourceException ex) {
            throw ex;
        } catch (Exception ex) {
            throw error("unable to issue self identity certificate: " + ex.getMessage());
        }
    }

    X509Certificate issueIdentity() throws Exception {

        final PrivateKey privateKey = KEY_ALGORITHM_EC.equals(keyAlgorithm) ? Crypto.generateECPrivateKey(EC_CURVE)
                : Crypto.generateRSAPrivateKey(RSA_KEY_SIZE);
        final GeneralName[] sanArray = (spiffeUri == null) ? null
                : new GeneralName[] { new GeneralName(GeneralName.uniformResourceIdentifier, spiffeUri) };
        final String csr = Crypto.generateX509CSR(privateKey, "cn=" + COMMON_NAME, sanArray);

        final Identity identity = certIssuer.issue(DOMAIN_NAME, SERVICE_NAME, csr, certExpiryMins);

        // some cert signers return the leaf certificate followed by its
        // intermediate certificates so the first one is our certificate

        final List<X509Certificate> certs = parseCertificates(identity.getCertificate());
        final X509Certificate cert = certs.get(0);
        validateCertificate(cert, privateKey);

        // the configured refresh interval is used as is, but we warn if
        // the certificate is going to expire before the next refresh

        if (System.currentTimeMillis() + refreshIntervalMillis >= cert.getNotAfter().getTime()) {
            LOGGER.warn("Self identity certificate expires at {} before the next refresh in {} ms",
                    cert.getNotAfter(), refreshIntervalMillis);
        }

        final String caCertBundle = identity.getCaCertBundle();
        final List<X509Certificate> caCerts = (caCertBundle == null || caCertBundle.isEmpty())
                ? Collections.emptyList() : parseCertificates(caCertBundle);

        store.storeIdentity(privateKey, certs, caCerts);

        LOGGER.info("Issued self identity certificate: service={} serial={} notAfter={}",
                COMMON_NAME, cert.getSerialNumber(), cert.getNotAfter());
        return cert;
    }

    List<X509Certificate> parseCertificates(final String pem) throws ServerResourceException {

        // the factory rejects input without any certificate data

        Collection<? extends Certificate> certs;
        try {
            certs = CertificateFactory.getInstance("X.509").generateCertificates(
                    new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)));
        } catch (CertificateException ex) {
            throw error("unable to parse certificate: " + ex.getMessage());
        }
        return certs.stream().map(X509Certificate.class::cast).toList();
    }

    void validateCertificate(X509Certificate cert, PrivateKey privateKey) throws ServerResourceException {

        final String commonName = Crypto.extractX509CertCommonName(cert);
        if (!COMMON_NAME.equals(commonName)) {
            throw error("unexpected certificate common name: " + commonName);
        }

        final PublicKey publicKey = Crypto.extractPublicKey(privateKey);
        if (!Arrays.equals(publicKey.getEncoded(), cert.getPublicKey().getEncoded())) {
            throw error("certificate public key does not match the generated private key");
        }

        if (cert.getNotAfter().getTime() <= System.currentTimeMillis()) {
            throw error("certificate has already expired: " + cert.getNotAfter());
        }
    }

    void scheduleRefresh(long delayMillis) {
        if (!scheduler.isShutdown()) {
            scheduler.schedule(this::refreshTask, delayMillis, TimeUnit.MILLISECONDS);
        }
    }

    void refreshTask() {

        // keep using the current certificate until it expires and
        // retry with a shorter interval if the refresh fails

        long delayMillis = refreshIntervalMillis;
        try {
            refreshIdentity();
        } catch (Exception ex) {
            LOGGER.error("Unable to refresh self identity certificate, retrying in {} ms: {}",
                    RETRY_INTERVAL_MILLIS, ex.getMessage());
            delayMillis = RETRY_INTERVAL_MILLIS;
        }
        scheduleRefresh(delayMillis);
    }

    private static ServerResourceException error(final String message) {
        LOGGER.error("SelfIdentityManager: {}", message);
        return new ServerResourceException(ServerResourceException.INTERNAL_SERVER_ERROR, message);
    }
}
