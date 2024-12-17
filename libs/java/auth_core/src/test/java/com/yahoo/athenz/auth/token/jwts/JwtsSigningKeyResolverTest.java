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
package com.yahoo.athenz.auth.token.jwts;

import com.yahoo.athenz.auth.util.CryptoException;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.util.Objects;

import static org.testng.Assert.*;

public class JwtsSigningKeyResolverTest {

    private final ClassLoader classLoader = this.getClass().getClassLoader();

    @Test
    public void testGetPublicKey() {

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(jwksUri, null, null);
        resolver.setMillisBetweenZtsCalls(1000);

        assertNotNull(resolver.getPublicKey("eckey1")); // ec key
        assertNotNull(resolver.getPublicKey("keyId")); // rsa key

        assertNull(resolver.getPublicKey("unknown"));
    }

    @Test
    public void testAthenzConfWithKeys() {

        System.setProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF,
                Objects.requireNonNull(classLoader.getResource("athenz.conf")).toString());

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(jwksUri, null, null);
        resolver.setMillisBetweenZtsCalls(1000);

        assertNotNull(resolver.getPublicKey("0"));
        assertNotNull(resolver.getPublicKey("keyId"));
        assertNotNull(resolver.getPublicKey("eckey1"));
        assertNull(resolver.getPublicKey("unknown"));

        System.clearProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF);
    }

    @Test
    public void testAthenzConfWithNoKeys() {

        System.setProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF,
                Objects.requireNonNull(classLoader.getResource("athenz-no-keys.conf")).toString());

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(jwksUri, null, null);
        resolver.setMillisBetweenZtsCalls(1000);

        assertNotNull(resolver.getPublicKey("keyId"));
        assertNotNull(resolver.getPublicKey("eckey1"));
        assertNull(resolver.getPublicKey("unknown"));

        System.clearProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF);

    }

    @Test
    public void testAthenzConfWithInvalidKeys() {

        System.setProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF,
                Objects.requireNonNull(classLoader.getResource("athenz-no-valid-keys.conf")).toString());

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(jwksUri, null, null);
        resolver.setMillisBetweenZtsCalls(1000);

        assertNotNull(resolver.getPublicKey("keyId"));
        assertNotNull(resolver.getPublicKey("eckey1"));
        assertNull(resolver.getPublicKey("unknown-1"));
        assertNull(resolver.getPublicKey("unknown-2"));
        assertNull(resolver.getPublicKey("unknown-3"));

        System.clearProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF);
    }

    @Test
    public void testSiaConfWithKeys() throws IOException {

        System.setProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF,
                new File("src/test/resources/athenz-no-keys.conf").getCanonicalPath());
        System.setProperty(JwtsSigningKeyResolver.ZTS_PROP_JWK_ATHENZ_CONF,
                new File("src/test/resources/athenz_sia_jwks.conf").getCanonicalPath());

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(jwksUri, null, null);
        resolver.setMillisBetweenZtsCalls(1000);

        assertNotNull(resolver.getPublicKey("keyId"));
        assertNotNull(resolver.getPublicKey("c6e34b18-fb1c-43bb-9de7-7edc8981b14d"));
        assertNull(resolver.getPublicKey("unknown"));

        System.clearProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF);
        System.clearProperty(JwtsSigningKeyResolver.ZTS_PROP_JWK_ATHENZ_CONF);
    }

    @Test
    public void testGetResourceRetrieverInvalidUrls() {
        try {
            new JwtsSigningKeyResolver("file://file", null, "proxy-unknown-uri");
            fail();
        } catch (IllegalArgumentException ignored) {
        }
        try {
            new JwtsSigningKeyResolver("unknown-uri", null, "http://localhost:1080");
            fail();
        } catch (CryptoException ex) {
            assertTrue(ex.getMessage().contains("Invalid jwks uri: unknown-uri"));
        }
    }
}
