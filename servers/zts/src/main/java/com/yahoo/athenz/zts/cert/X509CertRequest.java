package com.yahoo.athenz.zts.cert;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

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

    private PKCS10CertificationRequest certReq = null;
    private String instanceId = null;
    private String dnsSuffix = null;
    private String cn = null;
    private List<String> dnsNames = Collections.emptyList();
    
    public X509CertRequest(String csr) throws CryptoException {
        certReq = Crypto.getPKCS10CertRequest(csr);
        if (certReq == null) {
            throw new CryptoException("Invalid csr provided");
        }
    }
    
    public boolean parseDnsNames(String domain, String service, StringBuilder errorMsg) {
        
        final String prefix = service + "." + domain.replace('.', '-') + ".";
        dnsNames = Crypto.extractX509CSRDnsNames(certReq);
        String checkDnsSuffix = null;
        for (String dnsName : dnsNames) {
            int idx = dnsName.indexOf(ZTSConsts.ZTS_CERT_INSTANCE_ID);
            if (instanceId == null && idx != -1) {
                instanceId = dnsName.substring(0, idx);
                checkDnsSuffix = dnsName.substring(idx + ZTSConsts.ZTS_CERT_INSTANCE_ID.length());
            } else if (dnsSuffix == null && dnsName.startsWith(prefix)) {
                dnsSuffix = dnsName.substring(prefix.length());
            } else {
                errorMsg.append("Invalid SAN dnsName entry: ").append(dnsName);
                return false;
            }
        }
        
        // verify that our dns name suffixes match before returning success
        
        if (dnsSuffix != null && checkDnsSuffix != null && !dnsSuffix.equals(checkDnsSuffix)) {
            errorMsg.append("Mismatch DNS suffixes: ").append(dnsSuffix)
                .append(" vs. ").append(checkDnsSuffix);
            return false;
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

        Collection<List<?>> certAttributes = null;
        try {
            certAttributes = cert.getSubjectAlternativeNames();
        } catch (CertificateParsingException ex) {
            LOGGER.error("compareDnsNames: Unable to get cert SANS: {}", ex.getMessage());
            return false;
        }
        
        if (certAttributes == null) {
            LOGGER.error("compareDnsNames: Certificate does not have SANs");
            return false;
        }
        
        int dnsNameCount = 0;
        Iterator<List<?>> certAttrs = certAttributes.iterator();
        while (certAttrs.hasNext()) {
            List<?> altName = (List<?>) certAttrs.next();
            Integer nameType = (Integer) altName.get(0);
            if (nameType == 2) {
                final String dnsName = (String) altName.get(1);
                if (!dnsNames.contains(dnsName)) {
                    LOGGER.error("compareDnsNames - Unknown dnsName in certificate {}", dnsName);
                    return false;
                }
                dnsNameCount += 1;
            }
        }
        
        if (dnsNameCount != dnsNames.size()) {
            LOGGER.error("compareDnsNames - Mismatch of dnsNames in certificate ({}) and CSR ({})",
                    dnsNameCount, dnsNames.size());
            return false;
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
            
            LOGGER.error("compareCommonName: unable to extract csr cn: " + ex.getMessage());
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
        
        // the csr must only have 2 SAN dnsName attributes. one with the provider
        // dns suffix and the second one with instance id. If we have any additional
        // dns names then we'll reject the request right away
        
        if (!parseDnsNames(domain, service, errorMsg)) {
            return false;
        }
        
        // we need to make sure that instance id is provided and is non-empty
        
        if (instanceId == null || instanceId.isEmpty()) {
            errorMsg.append("CSR does not contain required instance id dnsName");
            return false;
        }
        
        // if specified, we must mak sure it matches to the given value
        
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
        
        if (dnsSuffix != null) {
            final String dnsResource = ZTSConsts.ZTS_RESOURCE_DNS + dnsSuffix;
            if (!authorizer.access(ZTSConsts.ZTS_ACTION_LAUNCH, dnsResource, providerService, null)) {
                errorMsg.append("Provider '").append(providerService.getFullName())
                    .append("' not authorized to handle ").append(dnsSuffix).append(" dns entries");
                return false;
            }
        }

        
        return true;
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
}
