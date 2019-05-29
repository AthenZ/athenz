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
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.yahoo.athenz.common.server.dns.HostnameResolver;
import com.yahoo.athenz.zts.ZTSConsts;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;

public class X509CertRequest {

    private static final Logger LOGGER = LoggerFactory.getLogger(X509CertRequest.class);
    private static final Pattern WHITESPACE_PATTERN = Pattern.compile("\\s+");

    protected PKCS10CertificationRequest certReq;
    protected String instanceId = null;
    protected String spiffeUri = null;
    protected String normCsrPublicKey = null;

    protected String cn;
    protected List<String> dnsNames;
    protected List<String> providerDnsNames;
    protected List<String> ipAddresses;
    protected List<String> uris;
    
    public X509CertRequest(String csr) throws CryptoException {

        certReq = Crypto.getPKCS10CertRequest(csr);
        if (certReq == null) {
            throw new CryptoException("Invalid csr provided");
        }


        // extract the dns names but we can't process them now
        // since we need to know what the provider and domain
        // allowed dns suffix values

        dnsNames = Crypto.extractX509CSRDnsNames(certReq);
        providerDnsNames = new ArrayList<>();

        ipAddresses = Crypto.extractX509CSRIPAddresses(certReq);

        // extract the common name for the request

        try {
            cn = Crypto.extractX509CSRCommonName(certReq);
        } catch (Exception ex) {
            throw new CryptoException("Unable to extract CN from CSR:" + ex.getMessage());
        }

        // extract our URI values

        uris = Crypto.extractX509CSRURIs(certReq);

        // process to make sure we only have a single spiffe uri
        // present in our request

        if (!extractSpiffeURI()) {
            throw new CryptoException("Invalid SPIFFE URI present in CSR");
        }
    }
    
    public PKCS10CertificationRequest getCertReq() {
        return certReq;
    }
    
    public void setCertReq(PKCS10CertificationRequest certReq) {
        this.certReq = certReq;
    }

    public boolean parseCertRequest(StringBuilder errorMsg) {
        
        // first we need to determine our instance id and dns suffix

        if (!extractInstanceId()) {
            errorMsg.append("CSR does not include required instance id entry");
            return false;
        }

        return true;
    }

    boolean extractInstanceId() {

        // first check to see if we have the instance id is provided
        // in the athenz uri field

        instanceId = X509CertUtils.extractReqeustInstanceIdFromURI(uris);

        // if we have no instance id from the URI, then we're going
        // to fetch it from the dns list

        if (instanceId == null) {
            instanceId = X509CertUtils.extractReqeustInstanceIdFromDnsNames(dnsNames);
        }

        return instanceId != null && !instanceId.isEmpty();
    }

    /**
     * Verifies that the CSR contains dnsName entries that have
     * one of the following provided dns suffixes.
     * @param providerDnsSuffixList dns suffixes registered for the provider
     * @param serviceDnsSuffix dns suffix registered for the service
     * @return true if all dnsNames in the CSR end with given suffixes
     */
    public boolean validateDnsNames(final List<String> providerDnsSuffixList, final String serviceDnsSuffix,
            final String instanceHostname, HostnameResolver hostnameResolver) {

        // if the CSR has no dns names then we have nothing to check

        if (dnsNames.isEmpty()) {
            return true;
        }

        // make sure our provider dns list is empty

        providerDnsNames.clear();

        // verify that our dns name suffixes match before returning success
        // if we have a match with our provider dns suffix then we're going
        // to keep track of those entries in a separate list so we can
        // send them to the provider for verification (provider does not
        // have knowledge about the additional service dns domain entries
        // so it doesn't need to get those

        final String serviceDnsSuffixCheck = (serviceDnsSuffix != null) ? "." + serviceDnsSuffix : null;
        List<String> providerDnsSuffixCheckList = null;
        if (providerDnsSuffixList != null && !providerDnsSuffixList.isEmpty()) {
            providerDnsSuffixCheckList = new ArrayList<>();
            for (String dnsSuffix : providerDnsSuffixList) {
                providerDnsSuffixCheckList.add("." + dnsSuffix);
            }
        }

        for (String dnsName : dnsNames) {
            if (!dnsSuffixCheck(dnsName, providerDnsSuffixCheckList, serviceDnsSuffixCheck,
                    instanceHostname, hostnameResolver)) {
                return false;
            }
        }

        return true;
    }

    boolean dnsSuffixCheck(final String dnsName, final List<String> providerDnsSuffixCheckList,
            final String serviceDnsSuffixCheck, final String instanceHostname,
             HostnameResolver hostnameResolver) {

        if (providerDnsSuffixCheckList != null) {
            for (String dnsSuffixCheck : providerDnsSuffixCheckList) {
                if (dnsName.endsWith(dnsSuffixCheck)) {
                    providerDnsNames.add(dnsName);
                    return true;
                }
            }
        }

        if (serviceDnsSuffixCheck != null && dnsName.endsWith(serviceDnsSuffixCheck)) {
            return true;
        }

        if (instanceHostnameCheck(dnsName, instanceHostname, hostnameResolver)) {
            return true;
        }

        LOGGER.error("dnsSuffixCheck - dnsName {} does not end with provider {} / service {} suffix or hostname {}",
                dnsName, providerDnsSuffixCheckList != null ? String.join(",", providerDnsSuffixCheckList) : "",
                serviceDnsSuffixCheck, instanceHostname);
        return false;
    }

    boolean instanceHostnameCheck(final String dnsName, final String instanceHostname, HostnameResolver hostnameResolver) {

        // make sure we have valid value to check for

        if (instanceHostname == null) {
            return false;
        }

        // if no match there is no need to check with resolver

        if (!dnsName.equalsIgnoreCase(instanceHostname)) {
            return false;
        }

        // if resolver is given we need to make sure the value given
        // is a valid hostname

        return hostnameResolver == null ? true : hostnameResolver.isValidHostname(instanceHostname);
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
            LOGGER.error("compareDnsNames - Mismatch of dnsNames in certificate ({}: {}) and CSR ({}: {})",
                    certDnsNames.size(), String.join(", ", certDnsNames),
                    dnsNames.size(), String.join(", ", dnsNames));
            return false;
        }
        
        for (String dnsName : dnsNames) {
            if (!certDnsNames.contains(dnsName)) {
                LOGGER.error("compareDnsNames - Unknown dnsName in csr {}, csr-set ({}), certificate-set ({})",
                        dnsName, String.join(", ", dnsNames), String.join(", ", certDnsNames));
                return false;
            }
        }
        
        return true;
    }

    /**
     * Compare instance id specified in this CSR and given X509 Certificate
     * to make sure they match.
     * @param reqInstanceId instance id specified in the request uri
     * @param cert X509 Certificate to compare against
     * @return true if both CSR and X509 Cert contain identical instance id
     */
    public boolean validateInstanceId(final String reqInstanceId, X509Certificate cert) {

        // if specified, we must make sure it matches to the given value

        if (!instanceId.equals(reqInstanceId)) {
            LOGGER.error("Instanceid mismatch  csr: {}, uri: {}", instanceId, reqInstanceId);
            return false;
        }

        final String certInstanceId = X509CertUtils.extractRequestInstanceId(cert);
        if (!instanceId.equals(certInstanceId)) {
            LOGGER.error("Instanceid mismatch  csr: {}, cert: {}", instanceId, certInstanceId);
            return false;
        }

        return true;
    }

    public boolean validateCommonName(String reqCommonName) {
        
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
    
    public boolean validatePublicKeys(final String publicKey) {

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

        if (!compareCsrPublicKey(publicKey)) {
            LOGGER.error("comparePublicKeys: Public key mismatch");
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

        if (!compareCsrPublicKey(certPublicKey)) {
            LOGGER.error("comparePublicKeys: Public key mismatch");
            return false;
        }

        return true;
    }

    boolean compareCsrPublicKey(final String publicKey) {
        Matcher matcher = WHITESPACE_PATTERN.matcher(publicKey);
        final String normPublicKey = matcher.replaceAll("");
        return normPublicKey.equals(normCsrPublicKey);
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

    boolean extractSpiffeURI() {

        // first extract the URI list from the request

        if (uris == null || uris.isEmpty()) {
            return true;
        }

        // we must only have a single spiffe uri in the list

        String spUri = null;
        for (String uri : uris) {

            if (!uri.toLowerCase().startsWith(ZTSConsts.ZTS_CERT_SPIFFE_URI)) {
                continue;
            }

            if (spUri != null) {
                LOGGER.error("Multiple SPIFFE URIs in the CSR: {}/{}", uri, spUri);
                return false;
            }

            spUri = uri;
        }

        spiffeUri = spUri;
        return true;
    }

    boolean validateSpiffeURI(final String domain, final String name, final String value) {

        // the expected default format is
        // spiffe://[<provider-cluster>/ns/]<athenz-domain>/sa/<athenz-service>
        // spiffe://[<provider-cluster>/ns/]<athenz-domain>/ra/<athenz-role>
        //
        // so we'll be validating that our request has:
        // spiffe://<provider-cluster>/ns/<domain>/<name>/<value> or
        // spiffe://<domain>/<name>/<value> or

        if (spiffeUri == null) {
            return true;
        }

        URI uri;
        try {
            uri = new URI(spiffeUri);
        } catch (URISyntaxException ex) {
            LOGGER.error("validateSpiffeURI: Unable to parse {}: {}", spiffeUri, ex.getMessage());
            return false;
        }

        final String uriPath = uri.getPath();
        final String uriHost = uri.getHost();

        if (uriPath == null || uriPath.isEmpty() || uriHost == null || uriHost.isEmpty()) {
            LOGGER.error("validateSpiffeURI: invalid uri {}", spiffeUri);
            return false;
        }

        // let's check to see if our path starts with our
        // namespace ns field and thus which format we're using

        boolean uriVerified = false;
        if (uriPath.startsWith("/ns/")) {
            final String path = "/ns/" + domain + "/" + name + "/" + value;
            uriVerified = uriPath.equalsIgnoreCase(path);
        } else {
            final String path = "/" + name + "/" + value;
            uriVerified = uriHost.equalsIgnoreCase(domain) && uriPath.equalsIgnoreCase(path);
        }

        if (!uriVerified) {
            LOGGER.error("validateSpiffeURI: invalid uri path/host: {}", spiffeUri);
        }

        return uriVerified;
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
    
    public List<String> getDnsNames() {
        return dnsNames;
    }

    public List<String> getProviderDnsNames() {
        return providerDnsNames;
    }

    public List<String> getUris() {
        return uris;
    }

    public List<String> getIpAddresses() {
        return ipAddresses;
    }
}
