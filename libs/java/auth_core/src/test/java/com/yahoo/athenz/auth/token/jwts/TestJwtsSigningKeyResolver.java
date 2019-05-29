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
package com.yahoo.athenz.auth.token.jwts;

import io.jsonwebtoken.JwsHeader;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import java.io.File;
import java.io.IOException;

import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;

public class TestJwtsSigningKeyResolver {

    @Test
    public void testGetConnection() throws IOException {

        final String oldConf = System.setProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF,
                "src/test/resources/athenz.conf");

        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(null, null);
        HttpsURLConnection con = resolver.getConnection("https://localhost:4443");
        assertNotNull(con);

        if (oldConf == null) {
            System.clearProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF);
        } else {
            System.setProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF, oldConf);
        }
    }

    @Test
    public void testResolveSingingKey() {

        final String oldConf = System.setProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF,
                "src/test/resources/athenz.conf");

        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(null, null);
        JwsHeader header = Mockito.mock(JwsHeader.class);
        Mockito.when(header.getKeyId())
                .thenReturn("eckey1")
                .thenReturn("unknown");

        // first we get eckey1 which exists

        java.security.Key key = resolver.resolveSigningKey(header, "body");
        assertNotNull(key);

        // next we get unknown

        key = resolver.resolveSigningKey(header, "body");
        assertNull(key);

        if (oldConf == null) {
            System.clearProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF);
        } else {
            System.setProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF, oldConf);
        }
    }

    @Test
    public void testLoadPublicKeysFromServerInvalidUri() {

        final String oldConf = System.setProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF,
                "src/test/resources/athenz.conf");

        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver("https://localhost:10099", null);
        assertNotNull(resolver);

        if (oldConf == null) {
            System.clearProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF);
        } else {
            System.setProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF, oldConf);
        }
    }

    @Test
    public void testGetSocketFactory() {

        final String oldConf = System.setProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF,
                "src/test/resources/athenz.conf");

        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(null, null);
        assertNull(resolver.getSocketFactory(null));

        if (oldConf == null) {
            System.clearProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF);
        } else {
            System.setProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF, oldConf);
        }
    }
}
