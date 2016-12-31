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
package com.yahoo.athenz.auth.impl;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;

public class CertificateAuthority implements Authority {

    private static final Logger LOG = LoggerFactory.getLogger(CertificateAuthority.class);

    @Override
    public void initialize() {
    }

    @Override
    public String getDomain() {
        return null;
    }

    @Override
    public String getHeader() {
        return null;
    }

    @Override
    public Principal authenticate(String creds, String remoteAddr, String httpMethod, StringBuilder errMsg) {
        return null;
    }

    @Override
    public CredSource getCredSource() {
        return CredSource.CERTIFICATE;
    }
    
    String extractX509CertCN(X509Certificate x509Cert) {
        
        String cn = null;
        try {
            String principalName = x509Cert.getSubjectX500Principal().getName();
            if (LOG.isDebugEnabled()) {
                LOG.debug("CertificateAuthority:authenticate: TLS Certificate Principal: " + principalName);
            }
            if (principalName != null && !principalName.isEmpty()) {
                
                // in case there are multiple CNs, we're only looking at the first one
                
                X500Name x500name = new X500Name(x509Cert.getSubjectX500Principal().getName());
                RDN cnRdn = x500name.getRDNs(BCStyle.CN)[0];
                cn = IETFUtils.valueToString(cnRdn.getFirst().getValue());
            }
        } catch (Exception ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("CertificateAuthority:authenticate: Unable to extract principal", ex);
            }
        }
        return cn;
    }
    
    @Override
    public Principal authenticate(X509Certificate[] certs, StringBuilder errMsg) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("CertificateAuthority:authenticate: TLS Certificates: " + certs);
            if (certs != null) {
                for (X509Certificate cert : certs) {
                    LOG.debug("CertificateAuthority:authenticate: TLS Certificate: " + cert);
                }
            }
        }

        errMsg = errMsg == null ? new StringBuilder(512) : errMsg;

        // make sure we have at least one valid certificate in our list
        
        if (certs == null || certs[0] == null) {
            errMsg.append("CertificateAuthority:authenticate: No certificate available in request");
            return null;
        }
        
        X509Certificate x509Cert = certs[0];
        String principalName = extractX509CertCN(x509Cert);
        if (principalName == null || principalName.isEmpty()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("CertificateAuthority:authenticate: Certificate principal is empty");
            }
            errMsg.append("CertificateAuthority:authenticate: Certificate principal is empty");
            return null;
        }
        
        // extract domain and service names from the name. We must have
        // a valid service identity in the form domain.service
        
        int idx = principalName.lastIndexOf('.');
        if (idx == -1) {
            errMsg.append("CertificateAuthority:authenticate: Principal is not a valid service identity: "
                    + principalName);
            return null;
        }
        
        String domain = principalName.substring(0, idx);
        String name = principalName.substring(idx + 1);
        
        // all the role members in Athenz are normalized to lower case so we need to make
        // sure our principal's name and domain are created with lower case as well
        
        SimplePrincipal princ = (SimplePrincipal) SimplePrincipal.create(domain.toLowerCase(),
                name.toLowerCase(), x509Cert.toString(), this);
        princ.setUnsignedCreds(x509Cert.getSubjectX500Principal().toString());
        return princ;
    }
}
