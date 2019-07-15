/*
 * Copyright 2019 Oath Holdings Inc.
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
package com.yahoo.athenz.zts.cert.impl.crypki;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import com.yahoo.athenz.instance.provider.InstanceProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This is an implementation of the Verizon Media's Crypki certificate signer.
 *          https://github.com/yahoo/crypki
 * Crypki is a service for interacting with an HSM or other PKCS #11 device.
 * It supports minting and signing of both SSH and x509 certificates.
 */
public class HttpCertSigner extends AbstractHttpCertSigner {

    private static final Logger LOGGER = LoggerFactory.getLogger(HttpCertSigner.class);

    private static final String X509_CERTIFICATE_PATH = "/sig/x509-cert/keys/x509-key";
    private static final String X509_KEY_META_IDENTIFIER = "x509-key";
    
    //default certificate expiration value of 30 days in seconds
    private static final int DEFAULT_CERT_EXPIRE_SECS = (int) TimeUnit.SECONDS.convert(30, TimeUnit.DAYS);

    @Override
    public String getX509CertUri(String serverBaseUri) {
        return serverBaseUri + X509_CERTIFICATE_PATH;
    }

    @Override
    public Object getX509CertSigningRequest(String csr, String keyUsage, int expireMins) {

        // Key Usage value used in Go - https://golang.org/src/crypto/x509/x509.go?s=18153:18173#L558
        // we're only interested in ExtKeyUsageClientAuth - with value of 2

        List<Integer> extKeyUsage = null;
        if (InstanceProvider.ZTS_CERT_USAGE_CLIENT.equals(keyUsage)) {
            extKeyUsage = new ArrayList<>();
            extKeyUsage.add(2);
        }

        X509CertificateSigningRequest csrCert = new X509CertificateSigningRequest();
        csrCert.setKeyMeta(new KeyMeta(X509_KEY_META_IDENTIFIER));
        csrCert.setCsr(csr);
        csrCert.setExtKeyUsage(extKeyUsage);
        csrCert.setValidity(DEFAULT_CERT_EXPIRE_SECS);
        
        if (expireMins > 0 && expireMins < getMaxCertExpiryTimeMins()) {
            //Validity period of the certificate in seconds in Crypki API.  Convert mins to seconds
            csrCert.setValidity((int) TimeUnit.SECONDS.convert(expireMins, TimeUnit.MINUTES));
        }
            
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("keyMeta: {} keyUsage: {} expireSec: {}", csrCert.getKeyMeta(),
                    csrCert.getExtKeyUsage(), csrCert.getValidity());
        }
        return csrCert;
    }

    @Override
    public String parseResponse(InputStream response) throws IOException {
        X509Certificate cert = JACKSON_MAPPER.readValue(response, X509Certificate.class);
        return cert.getCert();
    }
}
