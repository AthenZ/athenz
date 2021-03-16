/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.container;

import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.KeyStore;
import java.security.cert.*;
import java.util.Collection;

import static com.yahoo.athenz.common.ServerCommonConsts.SSL_CONNECTION_LOG_NAME;

public class AthenzServer extends SslContextFactory.Server {

    private static final Logger LOG = LoggerFactory.getLogger(SSL_CONNECTION_LOG_NAME);

    @Override
    protected TrustManager[] getTrustManagers(KeyStore trustStore, Collection<? extends CRL> crls) throws Exception {
        TrustManager[] trustManagers = super.getTrustManagers(trustStore, crls);

        if (trustManagers == null) {
            return null;
        }

        for (int i = 0; i < trustManagers.length; ++i) {
            if (X509TrustManager.class.isAssignableFrom(trustManagers[i].getClass())) {
                X509TrustManagerWithLogs x509TrustManagerWithLogs = new X509TrustManagerWithLogs((X509TrustManager) trustManagers[i]);
                trustManagers[i] = x509TrustManagerWithLogs;
            }
        }

        return trustManagers;
    }

    public static class X509TrustManagerWithLogs implements X509TrustManager {

        private final X509TrustManager x509TrustManager;

        public X509TrustManagerWithLogs(X509TrustManager x509TrustManager) {
            this.x509TrustManager = x509TrustManager;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
            try {
                x509TrustManager.checkClientTrusted(x509Certificates, s);
            } catch (CertificateException certificateException) {
                String certDetails = getCertDetails(x509Certificates);
                LOG.info("checkClientTrusted failed. Cert: {}", certDetails);
                throw certificateException;
            }
        }

        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
            try {
                x509TrustManager.checkServerTrusted(x509Certificates, s);
            } catch (CertificateException certificateException) {
                String certDetails = getCertDetails(x509Certificates);
                LOG.info("checkServerTrusted failed. Cert: {}", certDetails);
                throw certificateException;
            }
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return x509TrustManager.getAcceptedIssuers();
        }

        private String getCertDetails(Certificate[] certificates) {
            if (certificates == null || certificates.length == 0) {
                return "";
            }

            // Only print leaf cert
            X509Certificate leafCert = (X509Certificate) certificates[0];
            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.append("SubjectDN: " + leafCert.getSubjectDN());
            stringBuilder.append(" IssuerDN: " + leafCert.getIssuerDN());
            stringBuilder.append(" Validity Period: Valid from " + leafCert.getNotBefore() + " to "
                    + leafCert.getNotAfter());
            stringBuilder.append(" SN#: " + leafCert.getSerialNumber());
            stringBuilder.append(" SigAlgName: " + leafCert.getSigAlgName());

            return stringBuilder.toString();
        }

    }
}
