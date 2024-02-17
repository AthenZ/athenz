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
package com.yahoo.athenz.zts.cert.impl;

import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.server.cert.CertSigner;
import com.yahoo.athenz.common.server.cert.CertSignerFactory;
import com.yahoo.athenz.zts.ZTSConsts;

import java.io.File;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.IOException;

public class SelfCertSignerFactory implements CertSignerFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(SelfCertSignerFactory.class);

    @Override
    public CertSigner create() {
        
        // extract the private key for this self cert signer
        
        final String pKeyFileName = System.getProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_FNAME);
        final String pKeyPassword = System.getProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_PASSWORD);
        final String csrDn = System.getProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_CERT_DN,
                "CN=Self Signed Athenz CA, O=Athenz, C=US");
        final int maxCertExpiryTimeMins = Integer.parseInt(System.getProperty(ZTSConsts.ZTS_PROP_CERTSIGN_MAX_EXPIRY_TIME, "43200"));

        if (StringUtil.isEmpty(pKeyFileName)) {
            LOGGER.error("No private key path available for Self Cert Signer Factory");
            return null;
        }
        
        File caKey = new File(pKeyFileName);
        PrivateKey caPrivateKey = Crypto.loadPrivateKey(caKey, pKeyPassword);
        
        // now generate a CSR for our own CA and self sign it
        
        String csr;
        try {
            csr = Crypto.generateX509CSR(caPrivateKey, csrDn, null);
        } catch (IllegalArgumentException | OperatorCreationException | IOException | NoSuchAlgorithmException ex) {
            LOGGER.error("Unable to generate X509 CSR for dn: {}, error: {}", csrDn, ex.getMessage());
            return null;
        }
        
        // generate our self-signed certificate

        X500Name issuer = Crypto.utf8DEREncodedIssuer(csrDn);
        PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(csr);
        X509Certificate caCertificate = Crypto.generateX509Certificate(certReq,
                caPrivateKey, issuer, 365 * 24 * 60, true);

        return new KeyStoreCertSigner(caCertificate, caPrivateKey, maxCertExpiryTimeMins);
    }
}
