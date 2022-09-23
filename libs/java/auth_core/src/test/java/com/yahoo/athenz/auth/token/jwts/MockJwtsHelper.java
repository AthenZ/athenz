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

import org.mockito.Mockito;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class MockJwtsHelper extends JwtsHelper {

    private static String responseBody;
    private static int responseCode;

    public static void setResponseBody(final String body) {
        responseBody = body;
    }

    public static void setResponseCode(int code) {
        responseCode = code;
    }

    @Override
    public HttpsURLConnection getUrlConnection(final String serverUrl) throws IOException {
        HttpsURLConnection mock = Mockito.mock(HttpsURLConnection.class);
        Mockito.when(mock.getResponseCode()).thenReturn(responseCode);
        Mockito.when(mock.getInputStream()).thenReturn(new ByteArrayInputStream(responseBody.getBytes(StandardCharsets.UTF_8)));
        return mock;
    }

    @Override
    public SSLSocketFactory getSocketFactory(SSLContext sslContext) {
        return (sslContext == null) ? null : Mockito.mock(SSLSocketFactory.class);
    }
}
