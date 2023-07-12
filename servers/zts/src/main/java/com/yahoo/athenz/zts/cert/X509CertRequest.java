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
package com.yahoo.athenz.zts.cert;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.yahoo.athenz.common.server.dns.HostnameResolver;
import com.yahoo.athenz.common.utils.X509CertUtils;
import com.yahoo.athenz.zts.CertType;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.cache.DataCache;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;

public class X509CertRequest {

    private static final Logger LOGGER = LoggerFactory.getLogger(X509CertRequest.class);
    private static final Pattern WHITESPACE_PATTERN = Pattern.compile("\\s+");

    protected static final String SPIFFE_TRUST_DOMAIN = System.getProperty(ZTSConsts.ZTS_PROP_SPIFFE_TRUST_DOMAIN, "athenz.io");

    protected PKCS10CertificationRequest certReq;
    protected String instanceId;
    protected String uriHostname;
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

        // extract and set uriHostname, if present

        uriHostname = X509CertUtils.extractItemFromURI(uris, ZTSConsts.ZTS_CERT_HOSTNAME_URI);

        // extract instanceId

        // first check to see if we have the instance id is provided
        // in the athenz uri field

        instanceId = X509CertUtils.extractRequestInstanceIdFromURI(uris);

        // if we have no instance id from the URI, then we're going
        // to fetch it from the dns list

        if (instanceId == null) {
            instanceId = X509CertUtils.extractRequestInstanceIdFromDnsNames(dnsNames);
        }
    }

    public PKCS10CertificationRequest getCertReq() {
        return certReq;
    }

    public void setCertReq(PKCS10CertificationRequest certReq) {
        this.certReq = certReq;
    }

    /**
     * Verifies that the CSR contains dnsName entries that have
     * one of the following provided dns suffixes.
     * @param domainName name of the domain
     * @param serviceName name of the service
     * @param provider name of the provider for dns/hostname suffix checks
     * @param athenzSysDomainCache system domain cache object for suffix lists
     * @param serviceDnsSuffix dns suffix registered for the service
     * @param instanceHostname instance hostname
     * @param instanceHostCnames list of instance host cnames
     * @param hostnameResolver resolver to verify hostname is correct
     * @return true if all dnsNames in the CSR end with given suffixes
     */
    public boolean validateDnsNames(final String domainName, final String serviceName, final String provider,
            final DataCache athenzSysDomainCache, final String serviceDnsSuffix, final String instanceHostname,
            final List<String> instanceHostCnames, HostnameResolver hostnameResolver, StringBuilder errorMsg) {

        // if the CSR has no dns names then we have nothing to check

        if (dnsNames.isEmpty()) {
            return true;
        }

        // if we're given an instance host and cname fields then we're going to validate
        // to make sure it's correct for the given request. Any invalid host/cname field
        // value will cause the request to be rejected

        if (!validateInstanceHostname(provider, athenzSysDomainCache, instanceHostname, hostnameResolver)) {
            errorMsg.append("Unable to validate Instance hostname: ").append(instanceHostname);
            return false;
        }

        if (!validateInstanceCnames(provider, athenzSysDomainCache, domainName + "." + serviceName,
                instanceHostname, instanceHostCnames, hostnameResolver, errorMsg)) {
            return false;
        }

        // make sure our provider dns list is empty

        providerDnsNames.clear();

        // verify that our dns name suffixes match before returning success
        // if we have a match with our provider dns suffix then we're going
        // to keep track of those entries in a separate list so we can
        // send them to the provider for verification (provider does not
        // have knowledge about the additional service dns domain entries
        // so it doesn't need to get those). We also support the case of
        // wildcard based on the service name in the format of:
        // *.<service>.<domain-with-dashes>.<provider-dns-suffix>
        // so we'll generate and pass the prefix to the function to verify
        // and automatically skip those from sending to the provider

        final String wildCardPrefix = "*." + serviceName + "." + domainName.replace('.', '-') + ".";
        final String serviceDnsSuffixCheck = (serviceDnsSuffix != null) ? "." + serviceDnsSuffix : null;

        final List<String> providerDnsSuffixList = athenzSysDomainCache.getProviderDnsSuffixList(provider);

        for (String dnsName : dnsNames) {
            if (!dnsSuffixCheck(dnsName, providerDnsSuffixList, serviceDnsSuffixCheck, wildCardPrefix,
                    instanceHostname, instanceHostCnames)) {
                errorMsg.append(dnsName).append(" does not end with provider/service configured suffix or hostname");
                return false;
            }
        }

        return true;
    }

    private boolean validateInstanceHostname(final String provider, final DataCache athenzSysDomainCache,
            final String instanceHostname, HostnameResolver hostnameResolver) {

        // if we have no hostname configured then there is nothing to do

        if (instanceHostname == null || instanceHostname.isEmpty()) {
            return true;
        }

        // validate the provider is authorized to request hostnames with
        // the given prefix

        if (!isHostnameAllowed(provider, athenzSysDomainCache, instanceHostname)) {
            return false;
        }

        // final check comes from the hostname resolver

        return hostnameResolver == null || hostnameResolver.isValidHostname(instanceHostname);
    }

    /**
     * validateUriHostname ensures that the instanceHostname passed in request matches the hostname in SanURI
     * @param instanceHostname hostname set in the input request
     * @return true or false
     */
    boolean validateUriHostname(final String instanceHostname) {
        // If there is no hostname in SanURI, there is nothing to validate against input hostname
        if (uriHostname == null || uriHostname.isEmpty()) {
            return true;
        }

        return uriHostname.equals(instanceHostname);
    }

    boolean isHostnameAllowed(final String provider, final DataCache athenzSysDomainCache,
            final String instanceHostname) {

        // validate the provider is authorized to request hostnames with
        // the given prefix

        final List<String> providerHostnameAllowedSuffixList = athenzSysDomainCache.getProviderHostnameAllowedSuffixList(provider);
        final List<String> providerHostnameDeniedSuffixList = athenzSysDomainCache.getProviderHostnameDeniedSuffixList(provider);

        // make sure the hostname does not end with one of the denied
        // suffix values

        if (providerHostnameDeniedSuffixList != null) {
            for (String dnsSuffixCheck : providerHostnameDeniedSuffixList) {
                if (instanceHostname.endsWith(dnsSuffixCheck)) {
                    LOGGER.error("isHostnameAllowed - denied hostname dns suffix {}/{}", instanceHostname, dnsSuffixCheck);
                    return false;
                }
            }
        }

        // make sure the hostname ends with one of the allowed
        // suffix values

        boolean allowedHostName = false;
        if (providerHostnameAllowedSuffixList != null) {
            for (String dnsSuffixCheck : providerHostnameAllowedSuffixList) {
                if (instanceHostname.endsWith(dnsSuffixCheck)) {
                    allowedHostName = true;
                    break;
                }
            }
        }

        if (!allowedHostName) {
            LOGGER.error("isHostnameAllowed - not allowed hostname dns name {} in suffix list: {}",
                    instanceHostname, providerHostnameAllowedSuffixList != null ? String.join(",", providerHostnameAllowedSuffixList) : "");
            return false;
        }

        return true;
    }

    boolean validateInstanceCnames(final String provider, final DataCache athenzSysDomainCache,
            final String serviceFqn, final String instanceHostname, List<String> instanceHostCnames,
            HostnameResolver hostnameResolver, StringBuilder errorMsg) {

        // if we have no cname list provided then nothing to check

        if (instanceHostCnames == null || instanceHostCnames.isEmpty()) {
            return true;
        }

        // with a valid cname, we must have an instance hostname provided

        if (instanceHostname == null || instanceHostname.isEmpty()) {
             errorMsg.append("Instance Host CNAME list provided without Hostname");
             return false;
        }

        // verify that all the cnames are valid hostnames and the provider
        // is authorized to request them

        for (String cname : instanceHostCnames) {
            if (!isHostnameAllowed(provider, athenzSysDomainCache, cname)) {
                errorMsg.append("invalid cname provided for instance: ").append(cname);
                return false;
            }
        }

        // we must also have a resolver present and configured

        if (hostnameResolver != null) {
            if (!hostnameResolver.isValidHostCnameList(serviceFqn, instanceHostname, instanceHostCnames, CertType.X509)) {
                errorMsg.append(instanceHostname).append(" does not have all hosts in ")
                        .append(String.join(",", instanceHostCnames)).append(" as configured CNAMEs");
                return false;
            }

            return true;
        }

        errorMsg.append("Instance host name CNAME list provided without a valid hostname resolver");
        return false;
    }

    boolean dnsSuffixCheck(final String dnsName, final List<String> providerDnsSuffixList,
            final String serviceDnsSuffixCheck, final String wildCardPrefix, final String instanceHostname,
            final List<String> instanceHostCnames) {

        if (providerDnsSuffixList != null) {
            for (String dnsSuffixCheck : providerDnsSuffixList) {
                if (dnsName.endsWith(dnsSuffixCheck)) {

                    // if this entry happens to be a cname for a configured
                    // instance hostname then we're not going to add
                    // the entry to the list for the provider to be approved

                    if (instanceHostCnames != null && instanceHostCnames.contains(dnsName)) {
                        return true;
                    }

                    // if the hostname has the wildcard prefix based on the
                    // service identity, we're going to skip sending that to
                    // the provider for verification. we allow components
                    // between the service prefix name and the provider
                    // suffix (in case the provider needs to include possibly
                    // region/colo specific component

                    if (dnsName.startsWith(wildCardPrefix)) {
                        return true;
                    }

                    // add the name to the list to be verified

                    providerDnsNames.add(dnsName);
                    return true;
                }
            }
        }

        // if this is authorized by Athenz configuration then there is no need
        // to check with the provider

        if (serviceDnsSuffixCheck != null && dnsName.endsWith(serviceDnsSuffixCheck)) {
            return true;
        }

        // check if this is the requested hostname in which case we need the
        // provider to validate it

        if (dnsName.equalsIgnoreCase(instanceHostname)) {
            providerDnsNames.add(dnsName);
            return true;
        }

        // finally check if this is one of the requested cnames in which case
        // there is no need for the provider to validate since Athenz
        // has already done so with the hostname resolver

        if (instanceHostCnames != null && instanceHostCnames.contains(dnsName)) {
            return true;
        }

        LOGGER.error("dnsSuffixCheck - dnsName {} does not end with provider {} / service {} suffix or hostname {}",
                dnsName, providerDnsSuffixList != null ? String.join(",", providerDnsSuffixList) : "",
                serviceDnsSuffixCheck, instanceHostname);
        return false;
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
            String value = Crypto.extractX509CSRSubjectOUField(certReq);
            if (value == null) {
                return true;
            }

            // we have three values that we want to possible match against
            // a) provider callback specified value
            // b) provider name
            // c) configured set of valid ou names
            // in all cases the caller might ask for a restricted certificate
            // which cannot be used to talk to ZMS/ZTS - those have the
            // suffix of ":restricted" so if our value contains one of those
            // we'll strip it out before comparing

            if (value.endsWith(Crypto.CERT_RESTRICTED_SUFFIX)) {
                value = value.substring(0, value.length() - Crypto.CERT_RESTRICTED_SUFFIX.length());
            }
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

    public void setNormCsrPublicKey(String normCsrPublicKey) {
        this.normCsrPublicKey = normCsrPublicKey;
    }
    
    public String getCommonName() {
        return cn;
    }
    
    public String getInstanceId() {
        return instanceId;
    }

    public String getUriHostname() {
        return uriHostname;
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
