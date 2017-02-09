/**
 * Copyright 2016 Yahoo Inc.
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

import java.io.IOException;
import java.io.StringWriter;
import java.security.PublicKey;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;
import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.zts.Identity;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.cert.CertSigner;
import com.yahoo.athenz.zts.store.DataStore;

public class ZTSUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(DataStore.class);

    public static final String ZTS_DEFAULT_EXCLUDED_CIPHER_SUITES = "SSL_RSA_WITH_DES_CBC_SHA,"
            + "SSL_DHE_RSA_WITH_DES_CBC_SHA,SSL_DHE_DSS_WITH_DES_CBC_SHA,"
            + "SSL_RSA_EXPORT_WITH_RC4_40_MD5,SSL_RSA_EXPORT_WITH_DES40_CBC_SHA,"
            + "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA";
    public static final String ZTS_DEFAULT_EXCLUDED_PROTOCOLS = "SSLv2,SSLv3";
    
    private static final Pattern WHITESPACE_PATTERN = Pattern.compile("\\s+");
    
    public static int retrieveConfigSetting(String property, int defaultValue) {
        
        int settingValue;
        try {
            String propValue = System.getProperty(property);
            if (propValue == null) {
                return defaultValue;
            }
            
            settingValue = Integer.parseInt(propValue);
            
            if (settingValue <= 0) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("Invalid " + property + " value: " + propValue +
                            ", defaulting to " + defaultValue + " seconds");
                }
                settingValue = defaultValue;
            }
        } catch (Exception ex) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Invalid " + property + " value, defaulting to " +
                        defaultValue + " seconds: " + ex.getMessage());
            }
            settingValue = defaultValue;
        }
        
        return settingValue;
    }
    
    public static SslContextFactory createSSLContextObject(String[] clientProtocols) {
        
        String keyStorePath = System.getProperty(ZTSConsts.ZTS_PROP_KEYSTORE_PATH);
        String keyStorePassword = System.getProperty(ZTSConsts.ZTS_PROP_KEYSTORE_PASSWORD);
        String keyStoreType = System.getProperty(ZTSConsts.ZTS_PROP_KEYSTORE_TYPE, "PKCS12");
        String keyManagerPassword = System.getProperty(ZTSConsts.ZTS_PROP_KEYMANAGER_PASSWORD);
        String trustStorePath = System.getProperty(ZTSConsts.ZTS_PROP_TRUSTSTORE_PATH);
        String trustStorePassword = System.getProperty(ZTSConsts.ZTS_PROP_TRUSTSTORE_PASSWORD);
        String trustStoreType = System.getProperty(ZTSConsts.ZTS_PROP_TRUSTSTORE_TYPE, "PKCS12");
        String excludedCipherSuites = System.getProperty(ZTSConsts.ZTS_PROP_EXCLUDED_CIPHER_SUITES,
                ZTS_DEFAULT_EXCLUDED_CIPHER_SUITES);
        String excludedProtocols = System.getProperty(ZTSConsts.ZTS_PROP_EXCLUDED_PROTOCOLS,
                ZTS_DEFAULT_EXCLUDED_PROTOCOLS);
        Boolean wantClientAuth = Boolean.parseBoolean(System.getProperty(ZTSConsts.ZTS_PROP_WANT_CLIENT_CERT, "false"));
        
        SslContextFactory sslContextFactory = new SslContextFactory();
        if (keyStorePath != null) {
            LOGGER.info("createSSLContextObject: using SSL KeyStore path: " + keyStorePath);
            sslContextFactory.setKeyStorePath(keyStorePath);
        }
        if (keyStorePassword != null) {
            sslContextFactory.setKeyStorePassword(keyStorePassword);
        }
        sslContextFactory.setKeyStoreType(keyStoreType);

        if (keyManagerPassword != null) {
            sslContextFactory.setKeyManagerPassword(keyManagerPassword);
        }
        if (trustStorePath != null) {
            LOGGER.info("createSSLContextObject: using SSL TrustStore path: " + trustStorePath);
            sslContextFactory.setTrustStorePath(trustStorePath);
        }
        if (trustStorePassword != null) {
            sslContextFactory.setTrustStorePassword(trustStorePassword);
        }
        sslContextFactory.setTrustStoreType(trustStoreType);

        if (excludedCipherSuites.length() != 0) {
            sslContextFactory.setExcludeCipherSuites(excludedCipherSuites.split(","));
        }
        
        if (excludedProtocols.length() != 0) {
            sslContextFactory.setExcludeProtocols(excludedProtocols.split(","));
        }

        sslContextFactory.setWantClientAuth(wantClientAuth);
        if (clientProtocols != null) {
            sslContextFactory.setIncludeProtocols(clientProtocols);
        }

        return sslContextFactory;
    }
    
    public static final boolean emitMonmetricError(int errorCode, String caller, String domainName, Metric metric) {

        if (errorCode < 1) {
            return false;
        }
        if (caller == null || caller.length() == 0) {
            return false;
        }
        caller = caller.trim();
        String alphanum = "^[a-zA-Z0-9]*$";
        if (!caller.matches(alphanum)) {
            return false;
        }

        // Set 3 scoreboard error metrics:
        // (1) cumulative "ERROR" (of all zts request and error types)
        // (2) cumulative granular zts request and error type (eg-
        // "getdomainlist_error_400")
        // (3) cumulative error type (of all zts requests) (eg- "error_404")
        String errCode = Integer.toString(errorCode);
        metric.increment("ERROR");
        if (domainName != null) {
            metric.increment(caller.toLowerCase() + "_error_" + errCode, domainName);
        } else {
            metric.increment(caller.toLowerCase() + "_error_" + errCode);
        }
        metric.increment("error_" + errCode);

        return true;
    }
    
    public static boolean verifyCertificateRequest(String csr, String cn, String publicKey) {
        
        // verify that it contains the right common name
        // and the certificate matches to what we have
        // registered in ZMS

        try {
            PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(csr);
            if (certReq == null) {
                LOGGER.error("validateCertificateRequest: unable to parse PKCS10 cert request");
                return false;
            }

            if (!validateCertReqCommonName(certReq, cn)) {
                LOGGER.error("validateCertificateRequest: unable to validate PKCS10 cert request common name");
                return false;
            }

            if (publicKey != null) {
                if (!validateCertReqPublicKey(certReq, publicKey)) {
                    LOGGER.error("validateCertificateRequest: unable to validate PKCS10 cert request public key");
                    return false;
                }
            }
            
        } catch (CryptoException ex) {
            LOGGER.error("validateCertificateRequest: unable to generate identity certificate: "
                    + ex.getMessage());
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
            
            LOGGER.error("validateCertReqCommonName: unable to extract csr cn: "
                    + ex.getMessage());
        }
        
        if (cnCertReq == null) {
            LOGGER.error("validateCertReqCommonName - unable to extract csr cn: "
                    + certReq.toString());
            return false;
        }

        if (!cnCertReq.equalsIgnoreCase(cn)) {
            LOGGER.error("validateCertReqCommonName - cn mismatch: "
                    + cnCertReq + " vs. " + cn);
            return false;
        }

        return true;
    }
    
    public static boolean validateCertReqPublicKey(PKCS10CertificationRequest certReq,
            String ztsPublicKey) {

        JcaPEMKeyConverter pemConverter = new JcaPEMKeyConverter();
        PublicKey pubKey = null;
        try {
            pubKey = pemConverter.getPublicKey(certReq.getSubjectPublicKeyInfo());
        } catch (PEMException ex) {
            LOGGER.error("validateCertificatePublicKey: unable to get public: "
                    + ex.getMessage());
            return false;
        }
        StringWriter writer = new StringWriter();
        String csrPublicKey = "";
        try {
            try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
                pemWriter.writeObject(pubKey);
                pemWriter.flush();
                pemWriter.close();
            }
            csrPublicKey = writer.toString();
        } catch (IOException ex) {
            LOGGER.error("validateCertificatePublicKey: unable to convert public key to PEM: "
                    + ex.getMessage());
            return false;
        }
        
        // we are going to remove all whitespace, new lines
        // in order to compare the pem encoded keys
        
        Matcher matcher = WHITESPACE_PATTERN.matcher(csrPublicKey);
        String normCsrPublicKey = matcher.replaceAll("");

        matcher = WHITESPACE_PATTERN.matcher(ztsPublicKey);
        String normZtsPublicKey = matcher.replaceAll("");

        if (!normZtsPublicKey.equals(normCsrPublicKey)) {
            LOGGER.error("validateCertificatePublicKey: Public key mismatch: '{}' vs '{}'",
                    csrPublicKey, ztsPublicKey);
            return false;
        }
        
        return true;
    }
    
    public static Identity generateIdentity(CertSigner certSigner, String csr, String cn,
                                            String caPEMCertificate) {
        

        // generate a certificate for this certificate request

        String pemCert = certSigner.generateX509Certificate(csr);
        if (pemCert == null || pemCert.isEmpty()) {
            LOGGER.error("generateIdentity: CertSigner was unable to generate X509 certificate");
            return null;
        }
        
        return new Identity().setName(cn).setCertificate(pemCert).setCaCertBundle(caPEMCertificate);
    }
}
