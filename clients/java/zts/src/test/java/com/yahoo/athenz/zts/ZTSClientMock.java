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
package com.yahoo.athenz.zts;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;

import javax.net.ssl.SSLContext;
import javax.net.ssl.HostnameVerifier;

import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.util.Crypto;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import software.amazon.awssdk.services.sts.model.Credentials;

public class ZTSClientMock extends ZTSClient {

    private String csrUriVerifyValue;
    private List<String> csrDnsVerifyValues;

    public ZTSClientMock(String ztsUrl) {
        super(ztsUrl);
    }

    public ZTSClientMock(String ztsUrl, Principal identity) {
        super(ztsUrl, identity);
    }

    public ZTSClientMock(String ztsUrl, SSLContext sslContext) {
        super(ztsUrl, sslContext);
    }

    @Override
    PoolingHttpClientConnectionManager createConnectionManager(SSLContext sslContext, HostnameVerifier hostnameVerifier) {
        return null;
    }

    public void setCsrUriVerifyValue(final String uriValue) {
        csrUriVerifyValue = uriValue;
    }

    public void setCsrDnsVerifyValues(final List<String> dnsValues) {
        csrDnsVerifyValues = dnsValues;
    }

    @Override
    Credentials assumeAWSRole(String account, String roleName) {
        return Credentials.builder().accessKeyId("access").secretAccessKey("secret").sessionToken("token").build();
    }
    
    @Override
    public InstanceIdentity postInstanceRegisterInformation(InstanceRegisterInformation info,
            Map<String, List<String>> responseHeaders) {

        // if we're asked to validate any values we should do so here

        if (csrUriVerifyValue != null) {
            PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(info.getCsr());
            final List<String> values = Crypto.extractX509CSRURIs(certReq);
            if (values.size() != 1 || !csrUriVerifyValue.equals(values.get(0))) {
                throw new IllegalArgumentException("csr uri value not verified");
            }
        }

        if (csrDnsVerifyValues != null) {
            PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(info.getCsr());
            final List<String> dnsValues = Crypto.extractX509CSRDnsNames(certReq);
            if (!csrDnsVerifyValues.equals(dnsValues)) {
                throw new IllegalArgumentException("csr dns name value not verified");
            }
        }

        InstanceIdentity identity = new InstanceIdentity();
        Path path = Paths.get("./src/test/resources/test_cert.pem");
        try {
            identity.setX509Certificate(new String(Files.readAllBytes(path)));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return identity;
    }
}
