package com.yahoo.athenz.zts.cert;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.store.DataStore;

public class X509CertRequest {

    private static final Logger LOGGER = LoggerFactory.getLogger(DataStore.class);
    private static final Pattern WHITESPACE_PATTERN = Pattern.compile("\\s+");

    private PKCS10CertificationRequest certReq = null;
    private String instanceId = null;
    private String dnsSuffix = null;
    private String normCsrPublicKey = null;

    private String cn = null;
    private List<String> dnsNames = null;
    private List<String> ipAddresses = null;
    
    public X509CertRequest(String csr) throws CryptoException {
        certReq = Crypto.getPKCS10CertRequest(csr);
        if (certReq == null) {
            throw new CryptoException("Invalid csr provided");
        }
        
        dnsNames = Crypto.extractX509CSRDnsNames(certReq);
        ipAddresses = Crypto.extractX509CSRIPAddresses(certReq);
    }
    
    public PKCS10CertificationRequest getCertReq() {
        return certReq;
    }
    
    public void setCertReq(PKCS10CertificationRequest certReq) {
        this.certReq = certReq;
    }
    
    public boolean parseCertRequest(StringBuilder errorMsg) {
        
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
    public boolean compareDnsNames(X509Certificate cert) {

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
    
    public boolean compareCommonName(String reqCommonName) {
        
        try {
            cn = Crypto.extractX509CSRCommonName(certReq);
        } catch (Exception ex) {
            
            // we want to catch all the exceptions here as we want to
            // handle all the errors and not let container to return
            // standard server error
            
            LOGGER.error("compareCommonName: unable to extract csr cn: {}", ex.getMessage());
            return false;
        }
        
        if (!reqCommonName.equalsIgnoreCase(cn)) {
            LOGGER.error("compareCommonName - cn mismatch: {} vs. {}", reqCommonName, cn);
            return false;
        }

        return true;
    }
    
    public boolean validate(Principal providerService, String domain, String service,
            String reqInstanceId, Authorizer authorizer, StringBuilder errorMsg) {
        
        // parse the cert request (csr) to extract the DNS entries
        // along with IP addresses. Validate that all hostnames
        // include the same dns suffix and the instance id required
        // hostname is specified
        
        if (!parseCertRequest(errorMsg)) {
            return false;
        }
        
        // if specified, we must make sure it matches to the given value
        
        if (reqInstanceId != null && !instanceId.equals(reqInstanceId)) {
            errorMsg.append("Instance id mismatch - URI: ").append(reqInstanceId)
                .append(" CSR: ").append(instanceId);
            return false;
        }
        
        // validate the common name in CSR and make sure it
        // matches to the values specified in the info object
        
        final String infoCommonName = domain + "." + service;
        if (!compareCommonName(infoCommonName)) {
            errorMsg.append("Unable to validate CSR common name");
            return false;
        }
        
        // validate that the dnsSuffix used in the dnsName attribute has
        // been authorized to be used by the given provider
        
        if (dnsSuffix != null && authorizer != null) {
            final String dnsResource = ZTSConsts.ZTS_RESOURCE_DNS + dnsSuffix;
            if (!authorizer.access(ZTSConsts.ZTS_ACTION_LAUNCH, dnsResource, providerService, null)) {
                errorMsg.append("Provider '").append(providerService.getFullName())
                    .append("' not authorized to handle ").append(dnsSuffix).append(" dns entries");
                return false;
            }
        }
        
        return true;
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
    
    public boolean comparePublicKeys(String publicKey) {

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
    
    public boolean comparePublicKeys(X509Certificate cert) {
        
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
    
    public List<String> getIpAddresses() {
        return ipAddresses;
    }
}
