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
package com.yahoo.athenz.auth.oauth.validator;

import static org.testng.Assert.*;

import java.io.FileInputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import com.yahoo.athenz.auth.oauth.token.OAuthJwtAccessToken;
import com.yahoo.athenz.auth.oauth.token.OAuthJwtAccessTokenException;
import com.yahoo.athenz.auth.util.CryptoException;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class OAuthJwtAccessTokenValidatorTest {

    private final ClassLoader classLoader = this.getClass().getClassLoader();
    private OAuthJwtAccessTokenValidator baseValidator = null;
    private X509Certificate readCert(String resourceName) throws Exception {
        try (FileInputStream certIs = new FileInputStream(this.classLoader.getResource(resourceName).getFile())) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(certIs);
        }
    }

    @BeforeMethod
    public void initialize() throws Exception {
        this.baseValidator = new OAuthJwtAccessTokenValidator() {
            public void validate(OAuthJwtAccessToken jwt) {}
            public void validateClientId(OAuthJwtAccessToken jwt, String clientId) {}
            public void validateCertificateBinding(OAuthJwtAccessToken jwt, String certificateThumbprint) {}
        };
    }

    @Test
    public void testGetX509CertificateCommonName() throws Exception {
        // on null
        assertThrows(NullPointerException.class, () -> this.baseValidator.getX509CertificateCommonName(null));

        X509Certificate cert = this.readCert("jwt_ui.athenz.io.pem");
        assertEquals(this.baseValidator.getX509CertificateCommonName(cert), "ui.athenz.io");
    }

    @Test
    public void testGetX509CertificateThumbprint() throws Exception {
        // on null
        assertThrows(NullPointerException.class, () -> this.baseValidator.getX509CertificateThumbprint(null));

        X509Certificate cert = this.readCert("jwt_ui.athenz.io.pem");
        assertEquals(this.baseValidator.getX509CertificateThumbprint(cert), "zlkxyoX95le-Nv7OI0BxcjTOogvy9PGH-v_CBr_DsEk");
    }

    @Test
    public void testValidateCertificateBinding() throws Exception {
        final OAuthJwtAccessTokenValidator mock = Mockito.mock(OAuthJwtAccessTokenValidator.class, Mockito.CALLS_REAL_METHODS);

        // on CertificateEncodingException
        Mockito.doThrow(new CertificateEncodingException()).when(mock).getX509CertificateThumbprint(null);
        assertThrows(OAuthJwtAccessTokenException.class, () -> mock.validateCertificateBinding(null, (X509Certificate) null));
        // on CryptoException
        Mockito.doThrow(new CryptoException()).when(mock).getX509CertificateThumbprint(null);
        assertThrows(OAuthJwtAccessTokenException.class, () -> mock.validateCertificateBinding(null, (X509Certificate) null));

        // actual call
        OAuthJwtAccessTokenValidator validator = Mockito.mock(OAuthJwtAccessTokenValidator.class, Mockito.CALLS_REAL_METHODS);
        X509Certificate cert = this.readCert("jwt_ui.athenz.io.pem");
        Mockito.doReturn("zlkxyoX95le-Nv7OI0BxcjTOogvy9PGH-v_CBr_DsEk").when(validator).getX509CertificateThumbprint(cert);
        ArgumentCaptor<OAuthJwtAccessToken> tokenArg = ArgumentCaptor.forClass(OAuthJwtAccessToken.class);
        ArgumentCaptor<String> thumbprintArg = ArgumentCaptor.forClass(String.class);

        validator.validateCertificateBinding(null, cert);
        Mockito.verify(validator, Mockito.times(1)).validateCertificateBinding(tokenArg.capture(), thumbprintArg.capture());
        assertNull(tokenArg.getValue());
        assertEquals(thumbprintArg.getValue(), "zlkxyoX95le-Nv7OI0BxcjTOogvy9PGH-v_CBr_DsEk");
    }

}
