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
package com.yahoo.athenz.common.utils;

import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.util.Crypto;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

public class X509CertUtils {

    static final String ZTS_CERT_INSTANCE_ID_DNS = ".instanceid.athenz.";
    static final String ZTS_CERT_INSTANCE_ID_URI = "athenz://instanceid/";
    static final String ZTS_CERT_HOSTNAME_URI    = "athenz://hostname/";

    private static final Logger LOGGER = LoggerFactory.getLogger(X509CertUtils.class);
    private static final ThreadLocal<StringBuilder> TLS_BUILDER = ThreadLocal.withInitial(() -> new StringBuilder(256));

    public static String extractRequestInstanceIdFromURI(final List<String> uriList) {

        for (String uri : uriList) {
            if (!uri.startsWith(ZTS_CERT_INSTANCE_ID_URI)) {
                continue;
            }
            // skip the provider value
            int idx = uri.indexOf('/', ZTS_CERT_INSTANCE_ID_URI.length());
            if (idx != -1) {
                return uri.substring(idx + 1);
            }
        }

        return null;
    }

    /**
     * extractProvider derives the provider from athenz://instanceid San URI
     * @param cert X509Certificate
     * @return provider from San URI, "" if provider is not found.
     */
    public static String extractProvider(X509Certificate cert) {
        if (cert == null) {
            return "";
        }

        for (String uri : Crypto.extractX509CertURIs(cert)) {
            if (!uri.startsWith(ZTS_CERT_INSTANCE_ID_URI)) {
                continue;
            }
            // extract the first field after the prefix, separated by '/'
            int prefixLen = ZTS_CERT_INSTANCE_ID_URI.length();
            int idx = uri.indexOf('/', prefixLen);
            return idx == -1
                    ? ""
                    : uri.substring(prefixLen, idx);
        }

        return "";
    }


    public static String extractItemFromURI(final List<String> uriList, final String item) {

        for (String uri : uriList) {
            if (uri.startsWith(item)) {
                return uri.substring(item.length());
            }
        }

        return null;
    }

    public static String extractRequestInstanceIdFromDnsNames(final List<String> dnsNames) {

        for (String dnsName : dnsNames) {
            int idx = dnsName.indexOf(ZTS_CERT_INSTANCE_ID_DNS);
            if (idx != -1) {
                return dnsName.substring(0, idx);
            }
        }

        return null;
    }

    /**
     * extractHostname returns the hostname found in the athenz://hostname SanURI entry
     * @param cert X509Certficate
     * @return hostname found in SanURI, "" if no hostname is found
     */
    public static String extractHostname(X509Certificate cert) {
        if (cert == null) {
            return "";
        }

        String hostname = extractItemFromURI(Crypto.extractX509CertURIs(cert), ZTS_CERT_HOSTNAME_URI);
        return hostname == null ? "" : hostname;
    }

    public static String extractRequestInstanceId(X509Certificate cert) {

        if (cert == null) {
            return null;
        }

        // first we're going to look for our uri field to see
        // if we have an instance id uri available. the format is:
        // athenz://instanceid/<provider>/<instance-id>

        final List<String> uriList = Crypto.extractX509CertURIs(cert);
        final String instanceId = extractRequestInstanceIdFromURI(uriList);
        if (instanceId != null) {
            return instanceId;
        }

        // if no uri, then we'll fall back to our old dnsName field

        final List<String> dnsNames = Crypto.extractX509CertDnsNames(cert);
        return extractRequestInstanceIdFromDnsNames(dnsNames);
    }

    /**
     * extractKeyModulus is a helper function to extract the Key Modulus CN from the leaf certificate
     * present at the zeroth position in jakarta.servlet.request.X509Certificate
     * @param certs an array of X509Certificate
     * @return the string representing the key modulus
     */
    public static String extractKeyModulus(X509Certificate[] certs) {
        if (certs == null || certs.length == 0) {
            return "";
        }

        return extractKeyModulus(certs[0]);
    }

    /**
     * extractKeyModulus returns the modulus for the RSA public key in the certificate
     * @param cert X509Certificate to extract the key modulus from
     * @return modulus as string, and empty "" for non RSA certificate
     */
    public static String extractKeyModulus(X509Certificate cert) {
        try {
            RSAPublicKey pub = (RSAPublicKey) cert.getPublicKey();
            return pub.getModulus().toString(16);
        } catch (ClassCastException e) {
            LOGGER.error("unable to convert the public key to RSA", e);
        }

        return "";
    }

    /**
     * extracSubjectDn is a helper function to extract the Subject DN from the leaf certificate
     * present at the zeroth position in jakarta.servlet.request.X509Certificate
     * @param certs an array of X509Certificate
     * @return subject DN as a string
     */
    public static String extractSubjectDn(X509Certificate[] certs) {
        if (certs == null || certs.length == 0) {
            return "";
        }

        return extractSubjectDn(certs[0]);
    }

    /**
     * extractSubjectDn returns the DN from the certificate passed in
     * @param cert X509Certificate to extract the Subject DN from
     * @return the string representing Subject DN
     */
    public static String extractSubjectDn(X509Certificate cert) {
        return cert.getSubjectX500Principal().getName();
    }

    /**
     * extractCn is a helper function to extract the Subject CN from the leaf certificate
     * present at the zeroth position in jakarta.servlet.request.X509Certificate
     * @param certs an array of X509Certificate
     * @return the string representing Subject CN
     */
    public static String extractCn(X509Certificate[] certs) {
        if (certs == null || certs.length == 0) {
            return "";
        }

        return extractCn(certs[0]);
    }

    /**
     * extractCn returns CN portion of the Subject DN of the certificate
     * @param cert X509Certificate to extract the CN from
     * @return string representing the Subject CN
     */
    public static String extractCn(X509Certificate cert) {
        return Crypto.extractX509CertCommonName(cert);
    }

    /**
     * extractIssuerDn is a helper function to extract the Issuer DN from the leaf certificate
     * present at the zeroth position in jakarta.servlet.request.X509Certificate
     * @param certs an array of X509Certificate
     * @return the string representing issuer DN
     */
    public static String extractIssuerDn(X509Certificate[] certs) {
        if (certs == null || certs.length == 0) {
            return "";
        }

        return Crypto.extractIssuerDn(certs[0]);
    }

    /**
     * @deprecated use com.yahoo.athenz.auth.util.Crypto.extractIssuerDn instead
     * extractIssuerDn returns the IssuerDN from the certificate passed in
     * @param cert X509Certificate to extract the DN from
     * @return string with Issuer DN
     */
    @Deprecated
    public static String extractIssuerDn(X509Certificate cert) {
        return Crypto.extractIssuerDn(cert);
    }

    /**
     * extractIssuerCn is a helper function to extract the Issuer CN from the leaf certificate
     * present at the zeroth position in jakarta.servlet.request.X509Certificate
     * @param certs an array of X509Certificate
     * @return the string representing issuer CN
     */
    public static String extractIssuerCn(X509Certificate[] certs) {
        if (certs == null || certs.length == 0) {
            return "";
        }

        return extractIssuerCn(certs[0]);
    }

    /**
     * extractIssuerCn returns the CN portion of the Issuer DN from the certificate passed in
     * @param cert X509Certificate to extract the Issuer CN from
     * @return the string containing the issuer CN
     */
    public static String extractIssuerCn(X509Certificate cert) {
        return Crypto.extractX509CertIssuerCommonName(cert);
    }

    /**
     * hexKeyMod returns the HEX encoded string of SHA256 of the Key Modulus of the leaf certificate
     * present at the zeroth position in jakarta.servlet.request.X509Certificate
     * @param certs an array of X509Certificate
     * @param toUpperCase to indicate whether the hex encoded result should be upper case or not
     * @return the string with hex encoded of SHA256 of the Key Modulus of the leaf certificate
     */
    public static String hexKeyMod(X509Certificate[] certs, final boolean toUpperCase) {
        if (certs == null || certs.length == 0) {
            return "";
        }

        String modulus = X509CertUtils.extractKeyModulus(certs);
        if (modulus.isEmpty()) {
            return "";
        }

        if (toUpperCase) {
            modulus = modulus.toUpperCase();
        }

        return Hex.encodeHexString(Crypto.sha256(modulus.getBytes(StandardCharsets.UTF_8)));
    }

    public static void logCert(final Logger certLogger, final Principal principal,
                final String ip, final String provider, final String instanceId,
                final X509Certificate x509Cert) {

        if (certLogger == null) {
            return;
        }

        // generate our cert object log record and log it
        // with the given logger

        try {
            certLogger.info(logRecord(principal, ip, provider, instanceId, x509Cert));
        } catch (Exception ex) {
            LOGGER.error("Unable to generate certificate log record: {}", ex.getMessage());
        }
    }

    public static void logSSH(final Logger certLogger, final Principal principal, final String ip,
            final String service, final String instanceId) {

        if (certLogger == null) {
            return;
        }

        // our format is going to be as follows
        // <ip> <principal> <service> <instance-id>

        certLogger.info("{} {} {} {}", ip, principal, service, instanceId);
    }

    public static String logRecord(final Principal principal, final String ip, final String provider,
            final String instanceId, final X509Certificate x509Cert) {

        StringBuilder buf = TLS_BUILDER.get();
        buf.setLength(0);

        // our format is going to be as follows
        // <ip> <principal> <provider> <instance-id> <subject> <issuer> <serial> <expiry-date>

        buf.append(ip);
        buf.append(' ');

        // now append our principal. if this is an instance register
        // operation then we have no principal so we're going to
        // just use - to indicate no principal

        if (principal != null) {
            buf.append(principal.getFullName());
        } else {
            buf.append('-');
        }
        buf.append(' ');

        // next our provider

        buf.append(provider);
        buf.append(' ');

        // next our instance id

        if (instanceId != null) {
            buf.append('"');
            buf.append(instanceId);
            buf.append('"');
        } else {
            buf.append('-');
        }
        buf.append(' ');

        // next our subject

        buf.append('"');
        buf.append(x509Cert.getSubjectX500Principal().getName());
        buf.append('"');
        buf.append(' ');

        // next we have our issuer

        buf.append('"');
        buf.append(x509Cert.getIssuerX500Principal().getName());
        buf.append('"');
        buf.append(' ');

        // next we have our serial number

        buf.append(x509Cert.getSerialNumber().toString());
        buf.append(' ');

        // finally we have our expiry date in milliseconds

        buf.append(x509Cert.getNotAfter().getTime());

        return buf.toString();
    }
}
