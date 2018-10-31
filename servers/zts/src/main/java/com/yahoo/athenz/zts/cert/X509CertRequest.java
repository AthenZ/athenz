/*
 * Copyright 2017 Yahoo Inc.
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
package com.yahoo.athenz.zts.cert;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;
import com.yahoo.athenz.zts.ZTSConsts;

public class X509CertRequest {

    private static final Logger LOGGER = LoggerFactory.getLogger(X509CertRequest.class);
    private static final Pattern WHITESPACE_PATTERN = Pattern.compile("\\s+");

    protected PKCS10CertificationRequest certReq;
    protected String instanceId = null;
    protected String dnsSuffix = null;
    protected String normCsrPublicKey = null;

    protected String cn = null;
    protected List<String> dnsNames;
    protected List<String> ipAddresses;
    protected List<String> uris;
    
    public X509CertRequest(String csr) throws CryptoException {
        certReq = Crypto.getPKCS10CertRequest(csr);
        if (certReq == null) {
            throw new CryptoException("Invalid csr provided");
        }
        
        dnsNames = Crypto.extractX509CSRDnsNames(certReq);
        ipAddresses = Crypto.extractX509CSRIPAddresses(certReq);
        uris = Crypto.extractX509CSRURIs(certReq);
    }
    
    public PKCS10CertificationRequest getCertReq() {
        return certReq;
    }
    
    public void setCertReq(PKCS10CertificationRequest certReq) {
        this.certReq = certReq;
    }

    boolean parseCertRequest(StringBuilder errorMsg) {
        
        // first we need to determine our instance id and dns suffix

        for (String dnsName : dnsNames) {
            int idx = dnsName.indexOf(ZTSConsts.ZTS_CERT_INSTANCE_ID);
            if (instanceId == null && idx != -1) {
                instanceId = dnsName.substring(0, idx);
                dnsSuffix = dnsName.substring(idx + ZTSConsts.ZTS_CERT_INSTANCE_ID.length());
                break;
            }
        }
        
        // if we have no instance id or suffix, we have an invalid request
        
        if (instanceId == null || dnsSuffix == null || instanceId.isEmpty() || dnsSuffix.isEmpty()) {
            errorMsg.append("CSR does not include required instance id DNS hostname entry");
            return false;
        }
        
        // verify that our dns name suffixes match before returning success
        
        final String dnsSuffixCheck = "." + dnsSuffix;
        for (String dnsName : dnsNames) {
            if (!dnsName.endsWith(dnsSuffixCheck)) {
                errorMsg.append("DNS Name ").append(dnsName)
                    .append(" does not end with expected suffix: ").append(dnsSuffix);
                return false;
            }
        }
        
        return true;
    }

    /**
     * Compare dns Names specified in this CSR and given X509 Certificate
     * to make sure they match.
     * @param cert X509 Certificate to compare against
     * @return true if both CSR and X509 Cert contain identical dns names
     */
    public boolean validateDnsNames(X509Certificate cert) {

        List<String> certDnsNames = Crypto.extractX509CertDnsNames(cert);
        if (certDnsNames.size() != dnsNames.size()) {
            LOGGER.error("compareDnsNames - Mismatch of dnsNames in certificate ({}) and CSR ({})",
                    certDnsNames.size(), dnsNames.size());
            return false;
        }
        
        for (String dnsName : dnsNames) {
            if (!certDnsNames.contains(dnsName)) {
                LOGGER.error("compareDnsNames - Unknown dnsName in certificate {}", dnsName);
                return false;
            }
        }
        
        return true;
    }

    boolean extractCommonName() {
        try {
            cn = Crypto.extractX509CSRCommonName(certReq);
        } catch (Exception ex) {

            // we want to catch all the exceptions here as we want to
            // handle all the errors and not let container to return
            // standard server error

            LOGGER.error("compareCommonName: unable to extract csr cn: {}", ex.getMessage());
            return false;
        }
        return true;
    }

    public boolean validateCommonName(String reqCommonName) {
        
        if (!extractCommonName()) {
            return false;
        }
        
        if (!reqCommonName.equalsIgnoreCase(cn)) {
            LOGGER.error("compareCommonName - cn mismatch: {} vs. {}", reqCommonName, cn);
            return false;
        }

        return true;
    }

    public boolean validateSubjectOField(Set<String> validValues) {

        if (validValues == null || validValues.isEmpty()) {
            return true;
        }

        try {
            final String value = Crypto.extractX509CSRSubjectOField(certReq);
            if (value == null) {
                return true;
            }
            boolean res = validValues.contains(value);
            if (!res) {
                LOGGER.error("Failed to validate Subject O Field {}", value);
            }
            return res;
        } catch (CryptoException ex) {
            LOGGER.error("Unable to extract Subject O Field: {}", ex.getMessage());
            return false;
        }
    }

    public boolean validateSubjectOUField(final String provider, final String certSubjectOU,
            Set<String> validValues) {

        try {
            final String value = Crypto.extractX509CSRSubjectOUField(certReq);
            if (value == null) {
                return true;
            }
            // we have three values that we want to possible match against
            // a) provider callback specified value
            // b) provider name
            // c) configured set of valid ou names

            if (value.equalsIgnoreCase(certSubjectOU)) {
                return true;
            } else if (value.equalsIgnoreCase(provider)) {
                return true;
            } else if (validValues != null && !validValues.isEmpty() && validValues.contains(value)) {
                return true;
            } else {
                LOGGER.error("Failed to validate Subject OU Field {}", value);
            }
            return false;
        } catch (CryptoException ex) {
            LOGGER.error("Unable to extract Subject OU Field: {}", ex.getMessage());
            return false;
        }
    }

    boolean extractCsrPublicKey() {
        
        // if we have already extracted our public key
        // and normalized, then there is nothing to do
        
        if (normCsrPublicKey != null) {
            return true;
        }
        
        // otherwise process this request
        
        final String csrPublicKey = Crypto.extractX509CSRPublicKey(certReq);
        if (csrPublicKey == null) {
            LOGGER.error("comparePublicKeys: unable to get public key");
            return false;
        }
        
        // we are going to remove all whitespace, new lines
        // in order to compare the pem encoded keys
        
        Matcher matcher = WHITESPACE_PATTERN.matcher(csrPublicKey);
        normCsrPublicKey = matcher.replaceAll("");
        return true;
    }
    
    public boolean validatePublicKeys(String publicKey) {

        if (publicKey == null) {
            LOGGER.error("comparePublicKeys: No public key provided for validation");
            return false;
        }
        
        // we are going to remove all whitespace, new lines
        // in order to compare the pem encoded keys
        
        if (!extractCsrPublicKey()) {
            LOGGER.error("comparePublicKeys: Unable to extract CSR public key");
            return false;
        }

        Matcher matcher = WHITESPACE_PATTERN.matcher(publicKey);
        String normZtsPublicKey = matcher.replaceAll("");

        if (!normZtsPublicKey.equals(normCsrPublicKey)) {
            LOGGER.error("comparePublicKeys: Public key mismatch: '{}' vs '{}'",
                    normCsrPublicKey, normZtsPublicKey);
            return false;
        }
        
        return true;
    }
    
    public boolean validatePublicKeys(X509Certificate cert) {
        
        // we are going to remove all whitespace, new lines
        // in order to compare the pem encoded keys
        
        if (!extractCsrPublicKey()) {
            LOGGER.error("comparePublicKeys: Unable to extract CSR public key");
            return false;
        }
        
        String certPublicKey = Crypto.extractX509CertPublicKey(cert);
        if (certPublicKey == null) {
            LOGGER.error("unable to extract certificate public key");
            return false;
        }
        
        Matcher matcher = WHITESPACE_PATTERN.matcher(certPublicKey);
        String normCertPublicKey = matcher.replaceAll("");

        if (!normCertPublicKey.equals(normCsrPublicKey)) {
            LOGGER.error("comparePublicKeys: Public key mismatch: '{}' vs '{}'",
                    normCsrPublicKey, normCertPublicKey);
            return false;
        }
        
        return true;
    }

    public boolean validateIPAddress(final String ip) {

        // if we have no IP addresses in the request, then we're good

        if (ipAddresses.isEmpty()) {
            return true;
        }

        // if we have more than 1 IP address in the request then
        // we're going to reject it as we can't validate if those
        // multiple addresses are from the same host. In this
        // scenario a provider model must be used which supports
        // multiple IPs in a request

        if (ipAddresses.size() != 1) {
            LOGGER.error("Cert request contains multiple IP: {} addresses", ipAddresses.size());
            return false;
        }

        return ipAddresses.get(0).equals(ip);
    }

    boolean validateSpiffeURI(final String domain, final String name, final String value) {

        // the expected default format is
        // spiffe://<provider-cluster>/ns/<athenz-domain>/sa/<athenz-service>
        // spiffe://<provider-cluster>/ns/<athenz-domain>/ra/<athenz-role>
        // so we'll be validating that our request has:
        // spiffe://<provider-cluster>/ns/<domain>/<name>/<value>

        // first extract the URI list from the request

        if (uris == null || uris.isEmpty()) {
            return true;
        }

        // we must only have a single spiffe uri in the list

        if (uris.size() != 1) {
            LOGGER.error("validateSpiffeURI: invalid number {} of values in uri list",
                    uris.size());
            return false;
        }

        final String spiffeUri = uris.get(0);
        URI uri;
        try {
            uri = new URI(spiffeUri);
        } catch (URISyntaxException ex) {
            LOGGER.error("validateSpiffeURI: Unable to parse {}: {}", spiffeUri, ex.getMessage());
            return false;
        }

        if (uri.getScheme() == null || uri.getPath() == null) {
            LOGGER.error("validateSpiffeURI: invalid uri {}", spiffeUri);
            return false;
        }

        if (!uri.getScheme().equalsIgnoreCase("spiffe")) {
            LOGGER.error("validateSpiffeURI: invalid uri scheme: {} in {}",
                    uri.getScheme(), spiffeUri);
            return false;
        }

        final String path = "/ns/" + domain + "/" + name + "/" + value;
        if (!uri.getPath().equalsIgnoreCase(path)) {
            LOGGER.error("validateSpiffeURI: invalid uri path: {} vs {}",
                    path, uri.getPath());
            return false;
        }

        return true;
    }

    public void setNormCsrPublicKey(String normCsrPublicKey) {
        this.normCsrPublicKey = normCsrPublicKey;
    }
    
    public String getCommonName() {
        return cn;
    }
    
    public String getInstanceId() {
        return instanceId;
    }

    public String getDnsSuffix() {
        return dnsSuffix;
    }
    
    public List<String> getDnsNames() {
        return dnsNames;
    }

    public List<String> getUris() {
        return uris;
    }

    public List<String> getIpAddresses() {
        return ipAddresses;
    }
}
