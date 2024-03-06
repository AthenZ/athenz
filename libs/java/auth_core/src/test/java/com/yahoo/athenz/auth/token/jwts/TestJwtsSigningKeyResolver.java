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

import io.jsonwebtoken.JwsHeader;
import org.testng.annotations.Test;

import javax.net.ssl.SSLContext;

import static com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver.ZTS_PROP_JWK_ATHENZ_CONF;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.testng.Assert.*;
import static org.testng.AssertJUnit.assertNotNull;
import static org.testng.AssertJUnit.assertNull;

public class TestJwtsSigningKeyResolver {

    private void resetConfProperty(final String oldConf) {
        if (oldConf == null) {
            System.clearProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF);
        } else {
            System.setProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF, oldConf);
        }
    }

    @Test
    public void testResolveSigningKey() {

        final String oldConf = System.setProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF,
                "src/test/resources/athenz.conf");

        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(null, null);
        assertEquals(resolver.publicKeyCount(), 2);

        JwsHeader header = mock(JwsHeader.class);
        when(header.getKeyId())
                .thenReturn("eckey1")
                .thenReturn("unknown");

        // first we get eckey1 which exists

        java.security.Key key = resolver.resolveSigningKey(header, "body");
        assertNotNull(key);

        // next we get unknown

        key = resolver.resolveSigningKey(header, "body");
        assertNull(key);

        resetConfProperty(oldConf);
    }

    @Test
    public void testCanFetch() {
        JwtsSigningKeyResolver.setMillisBetweenZtsCalls(1000);
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(null, null);
        assertFalse(JwtsSigningKeyResolver.canFetchLatestJwksFromZts());
        JwtsSigningKeyResolver.setMillisBetweenZtsCalls(-1);
        assertTrue(JwtsSigningKeyResolver.canFetchLatestJwksFromZts());
    }

    @Test
    public void testLoadPublicKeysFromServerInvalidUri() {

        final String oldConf = System.setProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF,
                "src/test/resources/athenz.conf");

        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver("https://localhost:10099", null);
        assertNotNull(resolver);
        assertEquals(resolver.getJwksUri(), "https://localhost:10099");

        resetConfProperty(oldConf);
    }
    
    @Test
    public void testLoadJWKPublicKeysFromServer() {
        System.setProperty(ZTS_PROP_JWK_ATHENZ_CONF, TestJwtsSigningKeyResolver.class.getClassLoader().getResource("jwk/athenz.conf").getPath());
        JwtsSigningKeyResolver resolver = spy(new JwtsSigningKeyResolver("https://localhost:10099", mock(SSLContext.class), "http://localhost:8128"));
        assertNotNull(resolver);
        String ecKeys = "{\n" +
                "        \"keys\": [\n" +
                "            {\n" +
                "                \"kid\" : \"FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ\",\n" +
                "                \"kty\" : \"EC\",\n" +
                "                \"crv\" : \"prime256v1\",\n" +
                "                \"x\"   : \"SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74\",\n" +
                "                \"y\"   : \"lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI\",\n" +
                "                \"d\"   : \"0g5vAEKzugrXaRbgKG0Tj2qJ5lMP4Bezds1_sTybkfk\"\n" +
                "            }\n" +
                "        ]\n" +
                "    }";
        when(resolver.getHttpData(any(), any(), any())).thenReturn(ecKeys);
        resolver.loadPublicKeysFromServer();
        assertNotNull(resolver.getPublicKey("FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ"));
        assertNotNull(resolver.getPublicKey("c6e34b18-fb1c-43bb-9de7-7edc8981b14d"));
        verify(resolver).getHttpData(any(), any(), eq("http://localhost:8128"));
        System.clearProperty(ZTS_PROP_JWK_ATHENZ_CONF);
    }
}
