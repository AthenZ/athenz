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
package com.yahoo.athenz.auth.oauth.parser;

import static org.testng.Assert.*;
import java.io.FileReader;
import java.lang.reflect.Field;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.function.BiFunction;
import com.yahoo.athenz.auth.KeyStore;
import org.bouncycastle.util.io.pem.PemReader;
import org.mockito.Mockito;
import org.testng.annotations.Test;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SigningKeyResolver;
import io.jsonwebtoken.impl.DefaultClaims;
import io.jsonwebtoken.impl.DefaultJwsHeader;

public class KeyStoreJwkKeyResolverTest {

    private final ClassLoader classLoader = this.getClass().getClassLoader();
    private final DefaultJwsHeader baseJwsHeader = new DefaultJwsHeader();
    private final KeyStore baseKeyStore = new KeyStore() {
        public String getPublicKey(String domain, String service, String keyId) {
            return null;
        }
    };
    private final SigningKeyResolver basejwksResolver = new SigningKeyResolver() {
        public Key resolveSigningKey(JwsHeader header, Claims claims) { return null; }
        public Key resolveSigningKey(JwsHeader header, String plaintext) { return null; }
    };
    private final PublicKey basePublicKey = new PublicKey() {
        private static final long serialVersionUID = 1L;
        public String getFormat() { return null; }
        public byte[] getEncoded() { return null; }
        public String getAlgorithm() { return null; }
    };

    @Test
    public void testKeyStoreJwkKeyResolver() {
        BiFunction<Field, KeyStoreJwkKeyResolver, Object> getFieldValue = (f, object) -> {
            try {
                f.setAccessible(true);
                return f.get(object);
            } catch (IllegalArgumentException | IllegalAccessException e) {
                throw new RuntimeException(e);
            }
        };

        KeyStoreJwkKeyResolver resolver = new KeyStoreJwkKeyResolver(null, null, null);
        assertNotNull(resolver);
        for (Field f : resolver.getClass().getDeclaredFields()) {
            switch (f.getName()) {
                case "keyStore":
                    assertNull(getFieldValue.apply(f, resolver));
                    break;
                case "jwksResolver":
                    assertNotNull(getFieldValue.apply(f, resolver));
                    break;
            }
        }

        resolver = new KeyStoreJwkKeyResolver(null, "file:///", null);
        assertNotNull(resolver);
        for (Field f : resolver.getClass().getDeclaredFields()) {
            switch (f.getName()) {
                case "keyStore":
                    assertNull(getFieldValue.apply(f, resolver));
                    break;
                case "jwksResolver":
                    assertNotNull(getFieldValue.apply(f, resolver));
                    break;
            }
        }

        resolver = new KeyStoreJwkKeyResolver(baseKeyStore, "file:///", null);
        assertNotNull(resolver);
        for (Field f : resolver.getClass().getDeclaredFields()) {
            switch (f.getName()) {
                case "keyStore":
                    assertSame(getFieldValue.apply(f, resolver), baseKeyStore);
                    break;
                case "jwksResolver":
                    assertNotNull(getFieldValue.apply(f, resolver));
                    break;
            }
        }
    }

    @Test
    public void testResolveSigningKey() throws Exception {
        // mocks
        KeyStore keyStoreMock = Mockito.spy(baseKeyStore);
        SigningKeyResolver jwksResolverMock = Mockito.spy(basejwksResolver);

        // instance
        KeyStoreJwkKeyResolver resolver = new KeyStoreJwkKeyResolver(null, "file:///", null);
        Field keyStoreField = resolver.getClass().getDeclaredField("keyStore");
        keyStoreField.setAccessible(true);
        Field providerField = resolver.getClass().getDeclaredField("jwksResolver");
        providerField.setAccessible(true);
        providerField.set(resolver, jwksResolverMock);

        // args
        DefaultJwsHeader jwsHeader = new DefaultJwsHeader();
        DefaultClaims claims = new DefaultClaims();

        // 1. null key store, find in JWKS
        PublicKey pk11 = Mockito.spy(basePublicKey);
        Mockito.when(jwksResolverMock.resolveSigningKey(jwsHeader, claims)).thenReturn(pk11);
        jwsHeader.setKeyId("11");
        claims.setIssuer(null);
        assertSame(resolver.resolveSigningKey(jwsHeader, claims), pk11);

        // set key store mock
        keyStoreField.set(resolver, keyStoreMock);

        // 2. invalid issuer, find in JWKS
        PublicKey pk21 = Mockito.spy(basePublicKey);
        Mockito.when(jwksResolverMock.resolveSigningKey(jwsHeader, claims)).thenReturn(pk21);
        jwsHeader.setKeyId("21");
        claims.setIssuer(null);
        assertSame(resolver.resolveSigningKey(jwsHeader, claims), pk21);
        PublicKey pk22 = Mockito.spy(basePublicKey);
        Mockito.when(jwksResolverMock.resolveSigningKey(jwsHeader, claims)).thenReturn(pk22);
        jwsHeader.setKeyId("22");
        claims.setIssuer("");
        assertSame(resolver.resolveSigningKey(jwsHeader, claims), pk22);
        PublicKey pk23 = Mockito.spy(basePublicKey);
        Mockito.when(jwksResolverMock.resolveSigningKey(jwsHeader, claims)).thenReturn(pk23);
        jwsHeader.setKeyId("23");
        claims.setIssuer("domain23-----service23");
        assertSame(resolver.resolveSigningKey(jwsHeader, claims), pk23);
        // 2. invalid domain, find in JWKS
        PublicKey pk24 = Mockito.spy(basePublicKey);
        Mockito.when(jwksResolverMock.resolveSigningKey(jwsHeader, claims)).thenReturn(pk24);
        jwsHeader.setKeyId("24");
        claims.setIssuer("domain24.service24");
        assertSame(resolver.resolveSigningKey(jwsHeader, claims), pk24);

        // 3. found in key store, skip JWKS
        PublicKey pk31;

        try (PemReader reader = new PemReader(new FileReader(this.classLoader.getResource("jwt_public.key").getFile()))) {
            pk31 = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(reader.readPemObject().getContent()));
        }
        Mockito.when(jwksResolverMock.resolveSigningKey(jwsHeader, claims)).thenReturn(pk31);
        Mockito.when(keyStoreMock.getPublicKey("sys.auth", "service31", "31")).thenReturn("-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAy3c3TEePZZPaxqNU2xV4\nortsXrw1EXTNQj2QUgL8UOPaQS0lbHJtD1cbcCFnzfXRXTOGqh8l+XWTRIOlt4yU\n+mEhgR0/JKILTPwmS0fj3D1PT6IjZShuNyd4USVdcjfCRBRb9ExIptJyeTTUu0Uu\njWNEcGOWAkUZcsonmiEz7bIMVkGy5uYnWGbsKP51Zf/PFMb96RcHeE0ZUitIB4YK\n1bgHLyAEBJIka5mRC/jWq/mlq3jiP5RaVWbzQiJbrjuYWd1Vps/xnrABx6/4Ft/M\n0AnSQN0SYjc/nWT1yGPpCwtWmWUU5NNHd+w6TdgOjdu00wownwblovtEYED+rncb\n913qfBM98kNHyj357BSzlvhiwEH5Ayo9DTnx1j9HuJGZXzymVypuQXLu/tkHMEt+\nc4kytKJNi6MLiauy9xtXGLXgOvZUM8V0Z27Z6CTfCzWZ0nwnEWDdH+NJyusL6pJg\nEGUBh6E9fdJInV7YOCF+P9/19imPHrZ0blTXK1TDfKS/pCLOXO/OmmH+p+UxQ77O\npeP5wlt5Jem0ErSisl/Qxhh1OtJcLwFdA7uC7rOTMrSEGLO++5+CatsXj7BEK2l+\n3As8fJEkoWXd1+4KOUMfV/fnT/z6U8+bcsYn0nvWPl8XuMbwNWjqHYgqhl1RLA7M\n17HCydWCF50HI2XojtGgRN0CAwEAAQ==\n-----END PUBLIC KEY-----\n");
        jwsHeader.setKeyId("31");
        claims.setIssuer("sys.auth.service31");
        assertEquals(resolver.resolveSigningKey(jwsHeader, claims), pk31);
        // 3. NOT found in key store, find in JWKS
        PublicKey pk32 = Mockito.spy(basePublicKey);
        Mockito.when(jwksResolverMock.resolveSigningKey(jwsHeader, claims)).thenReturn(pk32);
        Mockito.when(keyStoreMock.getPublicKey("sys.auth", "service32", "32")).thenReturn(null);
        jwsHeader.setKeyId("32");
        claims.setIssuer("sys.auth.service32");
        assertSame(resolver.resolveSigningKey(jwsHeader, claims), pk32);
        // 3. found in key store but public key invalid, find in JWKS
        PublicKey pk33 = Mockito.spy(basePublicKey);
        Mockito.when(jwksResolverMock.resolveSigningKey(jwsHeader, claims)).thenReturn(pk33);
        Mockito.when(keyStoreMock.getPublicKey("sys.auth", "service33", "33")).thenReturn("");
        jwsHeader.setKeyId("33");
        claims.setIssuer("sys.auth.service33");
        assertSame(resolver.resolveSigningKey(jwsHeader, claims), pk33);
        PublicKey pk34 = Mockito.spy(basePublicKey);
        Mockito.when(jwksResolverMock.resolveSigningKey(jwsHeader, claims)).thenReturn(pk34);
        Mockito.when(keyStoreMock.getPublicKey("sys.auth", "service34", "34")).thenReturn("-----BEGIN PUBLIC KEY-----\ninvalid\n-----END PUBLIC KEY-----\n");
        jwsHeader.setKeyId("34");
        claims.setIssuer("sys.auth.service34");
        assertSame(resolver.resolveSigningKey(jwsHeader, claims), pk34);

        // 4. both NOT found
        jwsHeader.setKeyId("41");
        claims.setIssuer("sys.auth.service41");
        Mockito.when(jwksResolverMock.resolveSigningKey(jwsHeader, claims)).thenReturn(null);
        Mockito.when(keyStoreMock.getPublicKey("sys.auth", "service41", "41")).thenReturn(null);
        assertNull(resolver.resolveSigningKey(jwsHeader, claims));

        // 5. skip, empty key ID
        jwsHeader.setKeyId(null);
        claims.setIssuer(null);
        assertNull(resolver.resolveSigningKey(jwsHeader, claims));
        jwsHeader.setKeyId("");
        claims.setIssuer(null);
        assertNull(resolver.resolveSigningKey(jwsHeader, claims));
    }

    @Test
    public void testResolveSigningKeyForJwe() {
        KeyStoreJwkKeyResolver resolver = new KeyStoreJwkKeyResolver(null, "file:///", null);
        assertNull(resolver.resolveSigningKey(null, (String) null));
        assertNull(resolver.resolveSigningKey(null, ""));
        assertNull(resolver.resolveSigningKey(baseJwsHeader, "plaintext"));
    }

}
