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
package com.yahoo.athenz.zts.cert.impl.v2;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.cert.X509CertSignObject;

public class HttpCertSigner extends AbstractHttpCertSigner {
    private static final Logger LOGGER = LoggerFactory.getLogger(HttpCertSigner.class);
    private static final String X509_CERTIFICATE_PATH = "/x509";

    @Override
    public String getX509CertUri(String serverBaseUri) {
        return serverBaseUri + X509_CERTIFICATE_PATH;
    }

    @Override
    public Object getX509CertSigningRequest(String csr, String keyUsage, int expireMins) {
        List<Integer> extKeyUsage = null;
        if (ZTSConsts.ZTS_CERT_USAGE_CLIENT.equals(keyUsage)) {
            extKeyUsage = new ArrayList<>();
            extKeyUsage.add(2);
        }

        X509CertSignObject csrCert = new X509CertSignObject();
        csrCert.setPem(csr);
        csrCert.setX509ExtKeyUsage(extKeyUsage);
        if (expireMins > 0 && expireMins < getMaxCertExpiryTimeMins()) {
            csrCert.setExpiryTime(expireMins);
        }
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("keyUsage: {} expireMins: {}", csrCert.getX509ExtKeyUsage(), csrCert.getExpiryTime());
        }
        return csrCert;
    }

    @Override
    public String parseResponse(InputStream response) throws IOException {
        X509CertSignObject pemCert = JACKSON_MAPPER.readValue(response, X509CertSignObject.class);
        return pemCert.getPem();
    }
}
