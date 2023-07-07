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
package com.yahoo.athenz.zts.utils;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import com.oath.auth.KeyRefresher;
import com.oath.auth.Utils;
import com.yahoo.athenz.common.server.cert.Priority;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.eclipse.jetty.util.StringUtil;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.zts.Identity;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.cert.InstanceCertManager;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import java.security.KeyStore;
import java.security.SecureRandom;

import java.io.FileInputStream;

public class ZTSUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(ZTSUtils.class);

    static final String ZTS_DEFAULT_EXCLUDED_CIPHER_SUITES = "SSL_RSA_WITH_DES_CBC_SHA,"
            + "SSL_DHE_RSA_WITH_DES_CBC_SHA,SSL_DHE_DSS_WITH_DES_CBC_SHA,"
            + "SSL_RSA_EXPORT_WITH_RC4_40_MD5,SSL_RSA_EXPORT_WITH_DES40_CBC_SHA,"
            + "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA";
    static final String ZTS_DEFAULT_EXCLUDED_PROTOCOLS = "SSLv2,SSLv3";
    public static final List<String> ZTS_CERT_DNS_SUFFIX = Arrays.asList(
            System.getProperty(ZTSConsts.ZTS_PROP_CERT_DNS_SUFFIX, ZTSConsts.ZTS_CERT_DNS_SUFFIX).split(","));

    public static final long CERT_PRIORITY_MIN_PERCENT_LOW_PRIORITY = Long.parseLong(System.getProperty(ZTSConsts.ZTS_PROP_CERT_PRIORITY_MIN_PERCENT_LOW_PRIORITY, ZTSConsts.ZTS_CERT_PRIORITY_MIN_PERCENT_LOW_PRIORITY_DEFAULT));
    public static final long CERT_PRIORITY_MAX_PERCENT_HIGH_PRIORITY = Long.parseLong(System.getProperty(ZTSConsts.ZTS_PROP_CERT_PRIORITY_MAX_PERCENT_HIGH_PRIORITY, ZTSConsts.ZTS_CERT_PRIORITY_MAX_PERCENT_HIGH_PRIORITY_DEFAULT));

    private static final String ATHENZ_PROP_KEYSTORE_PATH               = "athenz.ssl_key_store";
    private static final String ATHENZ_PROP_KEYSTORE_TYPE               = "athenz.ssl_key_store_type";
    private static final String ATHENZ_PROP_KEYSTORE_PASSWORD           = "athenz.ssl_key_store_password";
    private static final String ATHENZ_PROP_KEYSTORE_PASSWORD_APPNAME   = "athenz.ssl_key_store_password_appname";

    private static final String ATHENZ_PROP_TRUSTSTORE_PATH             = "athenz.ssl_trust_store";
    private static final String ATHENZ_PROP_TRUSTSTORE_TYPE             = "athenz.ssl_trust_store_type";
    private static final String ATHENZ_PROP_TRUSTSTORE_PASSWORD         = "athenz.ssl_trust_store_password";
    private static final String ATHENZ_PROP_TRUSTSTORE_PASSWORD_APPNAME = "athenz.ssl_trust_store_password_appname";

    private static final String ATHENZ_PROP_PROVIDER_CLIENT_PUBLIC_CERT_PATH            = "athenz.zts.provider.ssl_client_public_cert_path";
    private static final String ATHENZ_PROP_PROVIDER_CLIENT_PRIVATE_KEY_PATH            = "athenz.zts.provider.ssl_client_private_key_path";
    private static final String ATHENZ_PROP_PROVIDER_CLIENT_TRUSTSTORE_PATH             = "athenz.zts.provider.ssl_client_trust_store";
    private static final String ATHENZ_PROP_PROVIDER_CLIENT_TRUSTSTORE_PASSWORD         = "athenz.zts.provider.ssl_client_trust_store_password";
    private static final String ATHENZ_PROP_PROVIDER_CLIENT_TRUSTSTORE_PASSWORD_APPNAME = "athenz.zts.provider.ssl_client_trust_store_password_appname";

    private final static char[] EMPTY_PASSWORD = "".toCharArray();

    public static SslContextFactory.Client createSSLContextObject(final String[] clientProtocols,
            final PrivateKeyStore privateKeyStore) {
        
        String keyStorePath = System.getProperty(ZTSConsts.ZTS_PROP_KEYSTORE_PATH);
        String keyStorePasswordAppName = System.getProperty(ZTSConsts.ZTS_PROP_KEYSTORE_PASSWORD_APPNAME);
        String keyStorePassword = System.getProperty(ZTSConsts.ZTS_PROP_KEYSTORE_PASSWORD);
        String keyStoreType = System.getProperty(ZTSConsts.ZTS_PROP_KEYSTORE_TYPE, "PKCS12");
        String keyManagerPassword = System.getProperty(ZTSConsts.ZTS_PROP_KEYMANAGER_PASSWORD);
        String keyManagerPasswordAppName = System.getProperty(ZTSConsts.ZTS_PROP_KEYMANAGER_PASSWORD_APPNAME);

        String trustStorePath = System.getProperty(ZTSConsts.ZTS_PROP_TRUSTSTORE_PATH);
        String trustStorePassword = System.getProperty(ZTSConsts.ZTS_PROP_TRUSTSTORE_PASSWORD);
        String trustStorePasswordAppName = System.getProperty(ZTSConsts.ZTS_PROP_TRUSTSTORE_PASSWORD_APPNAME);

        String trustStoreType = System.getProperty(ZTSConsts.ZTS_PROP_TRUSTSTORE_TYPE, "PKCS12");
        String excludedCipherSuites = System.getProperty(ZTSConsts.ZTS_PROP_EXCLUDED_CIPHER_SUITES,
                ZTS_DEFAULT_EXCLUDED_CIPHER_SUITES);
        String excludedProtocols = System.getProperty(ZTSConsts.ZTS_PROP_EXCLUDED_PROTOCOLS,
                ZTS_DEFAULT_EXCLUDED_PROTOCOLS);

        SslContextFactory.Client sslContextFactory = new SslContextFactory.Client();
        if (!StringUtil.isEmpty(keyStorePath)) {
            LOGGER.info("createSSLContextObject: using SSL KeyStore path: {}", keyStorePath);
            sslContextFactory.setKeyStorePath(keyStorePath);
        }
        
        if (!StringUtil.isEmpty(keyStorePassword)) {
            keyStorePassword = getApplicationSecret(privateKeyStore, keyStorePasswordAppName, keyStorePassword);
            sslContextFactory.setKeyStorePassword(keyStorePassword);
        }
        sslContextFactory.setKeyStoreType(keyStoreType);

        if (!StringUtil.isEmpty(keyManagerPassword)) {
            keyManagerPassword = getApplicationSecret(privateKeyStore, keyManagerPasswordAppName, keyManagerPassword);
            sslContextFactory.setKeyManagerPassword(keyManagerPassword);
        }
        
        if (!StringUtil.isEmpty(trustStorePath)) {
            LOGGER.info("createSSLContextObject: using SSL TrustStore path: {}", trustStorePath);
            sslContextFactory.setTrustStorePath(trustStorePath);
        }
        if (!StringUtil.isEmpty(trustStorePassword)) {
            trustStorePassword = getApplicationSecret(privateKeyStore, trustStorePasswordAppName, trustStorePassword);
            sslContextFactory.setTrustStorePassword(trustStorePassword);
        }
        sslContextFactory.setTrustStoreType(trustStoreType);

        sslContextFactory.setExcludeCipherSuites(excludedCipherSuites.split(","));
        sslContextFactory.setExcludeProtocols(excludedProtocols.split(","));

        if (clientProtocols != null) {
            sslContextFactory.setIncludeProtocols(clientProtocols);
        }

        return sslContextFactory;
    }
    
    static String getApplicationSecret(final PrivateKeyStore privateKeyStore,
            final String keyStorePasswordAppName, final String keyStorePassword) {
        return String.valueOf(getSecret(privateKeyStore, keyStorePasswordAppName, keyStorePassword));
    }

    static char[] getSecret(final PrivateKeyStore privateKeyStore,
                                       final String keyStorePasswordAppName, final String keyStorePassword) {

        if (privateKeyStore == null) {
            return keyStorePassword.toCharArray();
        }
        return privateKeyStore.getSecret(keyStorePasswordAppName, keyStorePassword);
    }
    
    public static boolean emitMonmetricError(int errorCode, String caller,
            String requestDomain, String principalDomain, Metric metric) {

        if (errorCode < 1) {
            return false;
        }
        if (StringUtil.isEmpty(caller)) {
            return false;
        }

        // Set 3 error metrics:
        // (1) cumulative "ERROR" (of all zts request and error types)
        // (2) cumulative granular zts request and error type (eg- "postaccesstoken_error_400")
        // (3) cumulative error type (of all zts requests) (eg- "error_404")
        final String errCode = Integer.toString(errorCode);
        metric.increment("ERROR");
        if (requestDomain != null) {
            metric.increment(caller.toLowerCase() + "_error_" + errCode, requestDomain, principalDomain);
        } else {
            metric.increment(caller.toLowerCase() + "_error_" + errCode);
        }
        metric.increment("error_" + errCode);

        return true;
    }

    public static boolean verifyCertificateRequest(PKCS10CertificationRequest certReq, final String domain, final String service) {
        
        // verify that it contains the right common name
        // and the certificate matches to what we have
        // registered in ZMS

        final String cn = domain + "." + service;
        if (!validateCertReqCommonName(certReq, cn)) {
            LOGGER.error("validateCertificateRequest: unable to validate PKCS10 cert request common name");
            return false;
        }

        // verify we don't have invalid dnsnames in the csr
        
        if (!validateCertReqDNSNames(certReq, domain, service)) {
            LOGGER.error("validateCertificateRequest: unable to validate PKCS10 cert request DNS Name");
            return false;
        }

        return true;
    }
    
    public static boolean validateCertReqCommonName(PKCS10CertificationRequest certReq, String cn) {
        
        String cnCertReq = null;
        try {
            cnCertReq = Crypto.extractX509CSRCommonName(certReq);
        } catch (Exception ex) {
            
            // we want to catch all the exceptions here as we want to
            // handle all the errors and not let container to return
            // standard server error
            
            LOGGER.error("validateCertReqCommonName: unable to extract csr cn: {}", ex.getMessage());
        }
        
        if (cnCertReq == null) {
            LOGGER.error("validateCertReqCommonName - unable to extract csr cn: {}", certReq.toString());
            return false;
        }

        if (!cnCertReq.equalsIgnoreCase(cn)) {
            LOGGER.error("validateCertReqCommonName - cn mismatch: {} vs. {}", cnCertReq, cn);
            return false;
        }

        return true;
    }
    
    static boolean validateCertReqDNSNames(PKCS10CertificationRequest certReq, final String domain,
            final String service) {
        
        // if no dns names in the CSR then we're ok
        
        List<String> dnsNames = Crypto.extractX509CSRDnsNames(certReq);
        if (dnsNames.isEmpty()) {
            return true;
        }
        
        // the only two formats we're allowed to have in the CSR are:
        // 1) <service>.<domain-with-dashes>.<provider-dns-suffix>
        // 2) <service>.<domain-with-dashes>.instanceid.athenz.<provider-dns-suffix>
        
        final String prefix = service + "." + domain.replace('.', '-') + ".";
        for (String dnsName : dnsNames) {
            if (dnsName.startsWith(prefix) && valueEndsWith(dnsName, ZTS_CERT_DNS_SUFFIX)) {
                continue;
            }
            if (dnsName.contains(ZTSConsts.ZTS_CERT_INSTANCE_ID_DNS)) {
                continue;
            }
            LOGGER.error("validateServiceCertReqDNSNames - Invalid dnsName SAN entry: {}", dnsName);
            return false;
        }

        return true;
    }
    
    public static String extractCertReqInstanceId(PKCS10CertificationRequest certReq) {
        List<String> dnsNames = Crypto.extractX509CSRDnsNames(certReq);
        String reqInstanceId = null;
        for (String dnsName : dnsNames) {
            int idx = dnsName.indexOf(ZTSConsts.ZTS_CERT_INSTANCE_ID_DNS);
            if (idx != -1) {
                reqInstanceId = dnsName.substring(0, idx);
                break;
            }
        }
        return reqInstanceId;
    }
    
    static boolean validateCertReqInstanceId(PKCS10CertificationRequest certReq, String instanceId) {
        final String reqInstanceId = extractCertReqInstanceId(certReq);
        if (reqInstanceId == null) {
            return false;
        }
        return reqInstanceId.equals(instanceId);
    }
    
    public static Identity generateIdentity(InstanceCertManager certManager, final String provider,
            final String certIssuer, final String csr, final String cn, final String certUsage,
            int expiryTime) {
        
        // generate a certificate for this certificate request

        String pemCert = certManager.generateX509Certificate(provider, certIssuer, csr, certUsage, expiryTime,
                Priority.Unspecified_priority);
        if (pemCert == null || pemCert.isEmpty()) {
            return null;
        }
        
        return new Identity().setName(cn).setCertificate(pemCert);
    }

    public static SSLContext getAthenzProviderClientSSLContext(PrivateKeyStore privateKeyStore) {

        // for truststore settings, we're going to default to the server truststore
        // settings if the client ones are not defined

        final String serverTrustStorePath = System.getProperty(ATHENZ_PROP_TRUSTSTORE_PATH);
        final String trustStorePath = System.getProperty(ATHENZ_PROP_PROVIDER_CLIENT_TRUSTSTORE_PATH, serverTrustStorePath);
        if (trustStorePath == null) {
            LOGGER.error("Unable to create client ssl context: no truststore path specified");
            return null;
        }
        final String certPath = System.getProperty(ATHENZ_PROP_PROVIDER_CLIENT_PUBLIC_CERT_PATH);
        if (certPath == null) {
            LOGGER.error("Unable to create client ssl context: no local ssl cert path specified");
            return null;
        }
        if (!new File(certPath).exists()) {
            LOGGER.error("Unable to create client ssl context: ssl cert not found in {}", certPath);
            return null;
        }
        final String keyPath = System.getProperty(ATHENZ_PROP_PROVIDER_CLIENT_PRIVATE_KEY_PATH);
        if (keyPath == null) {
            LOGGER.error("Unable to create client ssl context: no local ssl key path specified");
            return null;
        }
        if (!new File(keyPath).exists()) {
            LOGGER.error("Unable to create client ssl context: ssl key not found in {}", keyPath);
            return null;
        }

        final String serverTrustStorePassword = System.getProperty(ATHENZ_PROP_TRUSTSTORE_PASSWORD);
        final String trustStorePassword = System.getProperty(ATHENZ_PROP_PROVIDER_CLIENT_TRUSTSTORE_PASSWORD,
                serverTrustStorePassword);
        final String serverTrustStorePasswordAppName = System.getProperty(ATHENZ_PROP_TRUSTSTORE_PASSWORD_APPNAME);
        final String trustStorePasswordAppName = System.getProperty(ATHENZ_PROP_PROVIDER_CLIENT_TRUSTSTORE_PASSWORD_APPNAME,
                serverTrustStorePasswordAppName);
        try {
            final char[] passwordChars = getSecret(privateKeyStore, trustStorePasswordAppName, trustStorePassword);
            KeyRefresher keyRefresher = Utils.generateKeyRefresher(trustStorePath, passwordChars, certPath, keyPath);
            keyRefresher.startup();
            return Utils.buildSSLContext(keyRefresher.getKeyManagerProxy(), keyRefresher.getTrustManagerProxy());
        } catch (Exception ex) {
            LOGGER.error("Unable to create client ssl context. Error: {}", ex.getMessage());
            return null;
        }
    }

    public static SSLContext getAthenzServerSSLContext(PrivateKeyStore privateKeyStore) {
        final String keyStorePath = System.getProperty(ATHENZ_PROP_KEYSTORE_PATH);
        if (keyStorePath == null) {
            LOGGER.error("Unable to create client ssl context: no keystore path specified");
            return null;
        }
        final String keyStorePasswordAppName = System.getProperty(ATHENZ_PROP_KEYSTORE_PASSWORD_APPNAME);
        final String keyStorePassword = System.getProperty(ATHENZ_PROP_KEYSTORE_PASSWORD);
        final String keyStoreType = System.getProperty(ATHENZ_PROP_KEYSTORE_TYPE, "PKCS12");

        final String trustStorePath = System.getProperty(ATHENZ_PROP_TRUSTSTORE_PATH);
        if (trustStorePath == null) {
            LOGGER.error("Unable to create client ssl context: no truststore path specified");
            return null;
        }

        final String trustStorePassword = System.getProperty(ATHENZ_PROP_TRUSTSTORE_PASSWORD);
        final String trustStorePasswordAppName = System.getProperty(ATHENZ_PROP_TRUSTSTORE_PASSWORD_APPNAME);
        final String trustStoreType = System.getProperty(ATHENZ_PROP_TRUSTSTORE_TYPE, "PKCS12");

        SSLContext sslcontext = null;
        try {
            TrustManagerFactory tmfactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            try (FileInputStream instream = new FileInputStream(trustStorePath)) {
                KeyStore trustStore = KeyStore.getInstance(trustStoreType);
                final char[] password = getSecret(privateKeyStore, trustStorePasswordAppName, trustStorePassword);
                trustStore.load(instream, password != null ? password : EMPTY_PASSWORD);
                tmfactory.init(trustStore);
            }

            KeyManagerFactory kmfactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            try (FileInputStream instream = new FileInputStream(keyStorePath)) {
                KeyStore keyStore = KeyStore.getInstance(keyStoreType);
                final char[] password = getSecret(privateKeyStore, keyStorePasswordAppName, keyStorePassword);
                keyStore.load(instream, password != null ? password : EMPTY_PASSWORD);
                kmfactory.init(keyStore, password != null ? password : EMPTY_PASSWORD);
            }

            KeyManager[] keymanagers = kmfactory.getKeyManagers();
            TrustManager[] trustmanagers = tmfactory.getTrustManagers();

            sslcontext = SSLContext.getInstance("TLSv1.2");
            sslcontext.init(keymanagers, trustmanagers, new SecureRandom());
        } catch (Exception ex) {
            LOGGER.error("Unable to create server client ssl context", ex);
        }

        return sslcontext;
    }

    public static int parseInt(final String value, int defaultValue) {
        int intVal = defaultValue;
        if (value != null && !value.isEmpty()) {
            try {
                intVal = Integer.parseInt(value);
            } catch (NumberFormatException ex) {
                LOGGER.error("Invalid integer: {}", value);
            }
        }
        return intVal;
    }

    public static boolean parseBoolean(final String value, boolean defaultValue) {
        boolean boolVal = defaultValue;
        if (value != null && !value.isEmpty()) {
            boolVal = Boolean.parseBoolean(value);
        }
        return boolVal;
    }

    public static byte[] readFileContents(final String filename) {

        File file = new File(filename);

        byte[] data = null;
        try {
            data = Files.readAllBytes(Paths.get(file.toURI()));
        } catch (Exception ex) {
            LOGGER.error("Unable to read {}", filename, ex);
        }

        return data;
    }

    public static Priority getCertRequestPriority(Date notBefore, Date notAfter) {

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("CertPriority: PrevCertNotBefore: {}, PrevCertNotAfter: {}", notBefore, notAfter);
        }

        long certDuration = notAfter.getTime() - notBefore.getTime();
        long howLongStillValid = notAfter.getTime() - System.currentTimeMillis();

        // If certificate expired, high priority
        if (howLongStillValid <= 0) {
            return Priority.High;
        }

        long validityDurationPercentage = howLongStillValid * 100 / certDuration;
        if (validityDurationPercentage >= CERT_PRIORITY_MIN_PERCENT_LOW_PRIORITY) {
            return Priority.Low;
        } else if (validityDurationPercentage <= CERT_PRIORITY_MAX_PERCENT_HIGH_PRIORITY) {
            return Priority.High;
        } else {
            return Priority.Medium;
        }
    }

    public static boolean valueEndsWith(final String value, final List<String> suffixList) {
        for (String suffix : suffixList) {
            if (value.endsWith(suffix)) {
                return true;
            }
        }
        return false;
    }
}
