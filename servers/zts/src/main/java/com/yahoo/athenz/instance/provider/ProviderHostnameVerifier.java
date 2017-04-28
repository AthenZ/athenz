/**
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
package com.yahoo.athenz.instance.provider;

import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

public class ProviderHostnameVerifier implements HostnameVerifier {

    String dnsHostname = null;
    
    public ProviderHostnameVerifier(String hostname) {
        dnsHostname = hostname;
    }
    
    @Override
    public boolean verify(String hostname, SSLSession session) {

        Certificate[] certs = null;
        try {
            certs = session.getPeerCertificates();
        } catch (SSLPeerUnverifiedException e) {
        }
        if (certs == null) {
            return false;
        }
        
        for (Certificate cert : certs) {
            try {
                X509Certificate x509Cert = (X509Certificate) cert;
                if (matchDnsHostname(x509Cert.getSubjectAlternativeNames())) {
                    return true;
                }
            } catch (CertificateParsingException e) {
            }
        }
        return false;
    }
    
    boolean matchDnsHostname(Collection<List<?>> altNames) {
        
        if (altNames == null) {
            return false;
        }
        
        // GeneralName ::= CHOICE {
        //     otherName                       [0]     OtherName,
        //     rfc822Name                      [1]     IA5String,
        //     dNSName                         [2]     IA5String,
        //     x400Address                     [3]     ORAddress,
        //     directoryName                   [4]     Name,
        //     ediPartyName                    [5]     EDIPartyName,
        //     uniformResourceIdentifier       [6]     IA5String,
        //     iPAddress                       [7]     OCTET STRING,
        //     registeredID                    [8]     OBJECT IDENTIFIER}
        
        for (@SuppressWarnings("rawtypes") List item : altNames) {
            Integer type = (Integer) item.get(0);
            if (type == 2) {
                String dns = (String) item.get(1);
                if (dnsHostname.equalsIgnoreCase(dns)) {
                    return true;
                }
            }
        }
        
        return false;
    }
}
