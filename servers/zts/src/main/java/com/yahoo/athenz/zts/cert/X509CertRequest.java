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
    
    public boolean parseDnsNames(String domain, String service) {
        
        final String prefix = service + "." + domain.replace('.', '-') + ".";
        dnsNames = Crypto.extractX509CSRDnsNames(certReq);
        for (String dnsName : dnsNames) {
            if (dnsName.startsWith(ZTSConsts.ZTS_CERT_INSTANCE_ID_PREFIX)) {
                instanceId = dnsName.substring(ZTSConsts.ZTS_CERT_INSTANCE_ID_PREFIX.length());
            } else if (dnsName.startsWith(prefix)) {
                dnsSuffix = dnsName.substring(prefix.length());
            } else {
                LOGGER.error("parseDnsNames - Invalid dnsName SAN entry: {}", dnsName);
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
    
    public boolean validateCommonName(String reqCommonName) {
        
        try {
            cn = Crypto.extractX509CSRCommonName(certReq);
        } catch (Exception ex) {
            
            // we want to catch all the exceptions here as we want to
            // handle all the errors and not let container to return
            // standard server error
            
            LOGGER.error("validateCommonName: unable to extract csr cn: " + ex.getMessage());
            return false;
        }
        
        if (!reqCommonName.equalsIgnoreCase(cn)) {
            LOGGER.error("validateCommonName - cn mismatch: {} vs. {}", reqCommonName, cn);
            return false;
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
