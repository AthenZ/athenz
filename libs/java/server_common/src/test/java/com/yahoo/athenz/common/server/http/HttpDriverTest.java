/*
 * Copyright 2020 Verizon Media
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

package com.yahoo.athenz.common.server.http;

import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.HttpVersion;
import org.apache.http.NameValuePair;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.message.BasicStatusLine;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class HttpDriverTest {
    private ClassLoader classLoader = this.getClass().getClassLoader();

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testDriverThrowsException() throws IllegalArgumentException {
        new HttpDriver.Builder("", "/tmp/truststore-path", "asdf".toCharArray(), null, null)
                .maxPoolPerRoute(20)
                .maxPoolTotal(30)
                .clientRetryIntervalMs(5000)
                .clientMaxRetries(2)
                .clientConnectTimeoutMs(5000)
                .clientReadTimeoutMs(5000)
                .build();
    }

    @Test
    public void testDriverInit() {
        String caCertFile = classLoader.getResource("driver.truststore.jks").getFile();
        String certFile = classLoader.getResource("driver.cert.pem").getFile();
        String keyFile = classLoader.getResource("unit_test_driver.key.pem").getFile();

        // NOTE: the jks, cert, key are copied from cert refresher test resources
        // the jks had 123456 as the password
        HttpDriver httpDriver = new HttpDriver.Builder("", caCertFile, "123456".toCharArray(), certFile, keyFile)
                .maxPoolPerRoute(20)
                .maxPoolTotal(30)
                .clientRetryIntervalMs(5000)
                .clientMaxRetries(2)
                .clientConnectTimeoutMs(5000)
                .clientReadTimeoutMs(5000)
                .build();

        httpDriver.close();
    }

    @Test
    public void testDoGet() throws IOException {
        CloseableHttpClient httpClient = Mockito.mock(CloseableHttpClient.class);
        CloseableHttpResponse httpResponse = Mockito.mock(CloseableHttpResponse.class);
        HttpEntity entity = Mockito.mock(HttpEntity.class);

        String data = "Sample Server Response";

        Mockito.when(httpResponse.getStatusLine()).thenReturn(new BasicStatusLine(HttpVersion.HTTP_1_1, HttpStatus.SC_OK, "OK" ));
        Mockito.when(entity.getContent()).thenReturn(new ByteArrayInputStream(data.getBytes()));
        Mockito.when(httpResponse.getEntity()).thenReturn(entity);
        Mockito.when(httpClient.execute(Mockito.any(HttpGet.class))).thenReturn(httpResponse);

        HttpDriver httpDriver = new HttpDriver.Builder("", null, "asdf".toCharArray(), null, null)
                .build();

        httpDriver.setHttpClient(httpClient);

        String url = "https://localhost:4443/sample.html";

        String out = httpDriver.doGet(url);
        Assert.assertEquals(out, data);
    }

    @Test
    public void testDoGet404() throws IOException {
        CloseableHttpClient httpClient = Mockito.mock(CloseableHttpClient.class);
        CloseableHttpResponse httpResponse = Mockito.mock(CloseableHttpResponse.class);
        HttpEntity entity = Mockito.mock(HttpEntity.class);

        String data = "Not Found";

        Mockito.when(httpResponse.getStatusLine()).thenReturn(new BasicStatusLine(HttpVersion.HTTP_1_1, HttpStatus.SC_NOT_FOUND, "Not Found" ));
        Mockito.when(entity.getContent()).thenReturn(new ByteArrayInputStream(data.getBytes()));
        Mockito.when(httpResponse.getEntity()).thenReturn(entity);
        Mockito.when(httpClient.execute(Mockito.any(HttpGet.class))).thenReturn(httpResponse);

        HttpDriver httpDriver = new HttpDriver.Builder("", null, "asdf".toCharArray(), null, null)
                .build();

        httpDriver.setHttpClient(httpClient);

        String url = "https://localhost:4443/sample.html";

        String out = httpDriver.doGet(url);
        Assert.assertEquals(out, "");
    }

    @Test
    public void testDoGetException() throws IOException {
        CloseableHttpClient httpClient = Mockito.mock(CloseableHttpClient.class);
        CloseableHttpResponse httpResponse = Mockito.mock(CloseableHttpResponse.class);

        Mockito.when(httpClient.execute(Mockito.any(HttpGet.class))).thenThrow(new IOException("Unknown error"));

        HttpDriver httpDriver = new HttpDriver.Builder("", null, "asdf".toCharArray(), null, null)
                .build();

        httpDriver.setHttpClient(httpClient);

        String url = "https://localhost:4443/sample.html";

        try {
            httpDriver.doGet(url);
        } catch (IOException e) {
            Mockito.verify(httpClient, Mockito.times(2)).execute(Mockito.any(HttpGet.class));
        }
    }

    @Test
    public void testDoGetExecuteNullResponse() throws IOException {
        CloseableHttpClient httpClient = Mockito.mock(CloseableHttpClient.class);
        Mockito.when(httpClient.execute(Mockito.any(HttpGet.class))).thenReturn(null);

        HttpDriver httpDriver = new HttpDriver.Builder("", null, "asdf".toCharArray(), null, null)
                .build();
        httpDriver.setHttpClient(httpClient);

        String url = "https://localhost:4443/sample.html";
        try {
            httpDriver.doGet(url);
        } catch (IOException e) {
            Mockito.verify(httpClient, Mockito.times(2)).execute(Mockito.any(HttpGet.class));
        }
    }

    @Test
    public void testDoPostHttpPost() throws IOException {
        CloseableHttpClient httpClient = Mockito.mock(CloseableHttpClient.class);
        CloseableHttpResponse httpResponse = Mockito.mock(CloseableHttpResponse.class);
        HttpEntity responseEntity = Mockito.mock(HttpEntity.class);

        String data = "Sample Server Response";

        Mockito.when(httpResponse.getStatusLine()).thenReturn(new BasicStatusLine(HttpVersion.HTTP_1_1, HttpStatus.SC_OK, "OK" ));
        Mockito.when(responseEntity.getContent()).thenReturn(new ByteArrayInputStream(data.getBytes()));
        Mockito.when(httpResponse.getEntity()).thenReturn(responseEntity);
        Mockito.when(httpClient.execute(Mockito.any(HttpPost.class))).thenReturn(httpResponse);

        HttpDriver httpDriver = new HttpDriver.Builder("", null, "asdf".toCharArray(), null, null)
                .build();
        httpDriver.setHttpClient(httpClient);

        HttpPost httpPost = new HttpPost("https://localhost:4443/sample");

        // prepare POST body
        String body = "<?xml version='1.0'?><methodCall><methodName>test.test</methodName></methodCall>";

        // set POST body
        HttpEntity entity = new StringEntity(body);
        httpPost.setEntity(entity);

        String out = httpDriver.doPost(httpPost);
        Assert.assertEquals(out, data);
    }

    @Test
    public void testDoPostHttpPostResponse() throws IOException {
        CloseableHttpClient httpClient = Mockito.mock(CloseableHttpClient.class);
        CloseableHttpResponse httpResponse = Mockito.mock(CloseableHttpResponse.class);
        HttpEntity responseEntity = Mockito.mock(HttpEntity.class);

        String data = "Sample Server Response";

        Mockito.when(httpResponse.getStatusLine()).thenReturn(new BasicStatusLine(HttpVersion.HTTP_1_1, HttpStatus.SC_OK, "OK" ));
        Mockito.when(responseEntity.getContent()).thenReturn(new ByteArrayInputStream(data.getBytes()));
        Mockito.when(httpResponse.getEntity()).thenReturn(responseEntity);
        Mockito.when(httpClient.execute(Mockito.any(HttpPost.class))).thenReturn(httpResponse);

        HttpDriver httpDriver = new HttpDriver.Builder("", null, "asdf".toCharArray(), null, null)
                .build();
        httpDriver.setHttpClient(httpClient);

        HttpPost httpPost = new HttpPost("https://localhost:4443/sample");

        // prepare POST body
        String body = "<?xml version='1.0'?><methodCall><methodName>test.test</methodName></methodCall>";

        // set POST body
        HttpEntity entity = new StringEntity(body);
        httpPost.setEntity(entity);

        HttpDriverResponse httpDriverResponse = httpDriver.doPostHttpResponse(httpPost);
        Assert.assertEquals(httpDriverResponse.getMessage(), data);
        Assert.assertEquals(httpDriverResponse.getStatusCode(), HttpStatus.SC_OK);
    }

    @Test
    public void testDoPostHttpPostResponseFailure() throws IOException {
        CloseableHttpClient httpClient = Mockito.mock(CloseableHttpClient.class);
        CloseableHttpResponse httpResponse = Mockito.mock(CloseableHttpResponse.class);
        HttpEntity responseEntity = Mockito.mock(HttpEntity.class);

        String data = "ERROR RESPONSE FROM SERVER";

        Mockito.when(httpResponse.getStatusLine()).thenReturn(new BasicStatusLine(HttpVersion.HTTP_1_1, HttpStatus.SC_BAD_GATEWAY, "BAD-GATEWAY" ));
        Mockito.when(responseEntity.getContent()).thenReturn(new ByteArrayInputStream(data.getBytes()));
        Mockito.when(httpResponse.getEntity()).thenReturn(responseEntity);
        Mockito.when(httpClient.execute(Mockito.any(HttpPost.class))).thenReturn(httpResponse);

        HttpDriver httpDriver = new HttpDriver.Builder("", null, "asdf".toCharArray(), null, null)
                .build();
        httpDriver.setHttpClient(httpClient);

        HttpPost httpPost = new HttpPost("https://localhost:4443/sample");

        // prepare POST body
        String body = "<?xml version='1.0'?><methodCall><methodName>test.test</methodName></methodCall>";

        // set POST body
        HttpEntity entity = new StringEntity(body);
        httpPost.setEntity(entity);

        HttpDriverResponse httpDriverResponse = httpDriver.doPostHttpResponse(httpPost);
        Assert.assertEquals(httpDriverResponse.getMessage(), data);
        Assert.assertEquals(httpDriverResponse.getStatusCode(), HttpStatus.SC_BAD_GATEWAY);
    }

    @Test
    public void testDoPost200() throws IOException {
        CloseableHttpClient httpClient = Mockito.mock(CloseableHttpClient.class);
        CloseableHttpResponse httpResponse = Mockito.mock(CloseableHttpResponse.class);
        HttpEntity entity = Mockito.mock(HttpEntity.class);

        String data = "Sample Server Response";

        Mockito.when(httpResponse.getStatusLine()).thenReturn(new BasicStatusLine(HttpVersion.HTTP_1_1, HttpStatus.SC_OK, "OK" ));
        Mockito.when(entity.getContent()).thenReturn(new ByteArrayInputStream(data.getBytes()));
        Mockito.when(httpResponse.getEntity()).thenReturn(entity);
        Mockito.when(httpClient.execute(Mockito.any(HttpPost.class))).thenReturn(httpResponse);

        HttpDriver httpDriver = new HttpDriver.Builder("", null, "asdf".toCharArray(), null, null)
                .build();
        httpDriver.setHttpClient(httpClient);

        List<NameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("data", "value"));

        String url = "https://localhost:4443/sample";

        String out = httpDriver.doPost(url, params);
        Assert.assertEquals(out, data);
    }

    @Test
    public void testDoPost201() throws IOException {
        CloseableHttpClient httpClient = Mockito.mock(CloseableHttpClient.class);
        CloseableHttpResponse httpResponse = Mockito.mock(CloseableHttpResponse.class);
        HttpEntity entity = Mockito.mock(HttpEntity.class);

        String data = "Sample Server Response";

        Mockito.when(httpResponse.getStatusLine()).thenReturn(new BasicStatusLine(HttpVersion.HTTP_1_1, HttpStatus.SC_CREATED, "OK" ));
        Mockito.when(entity.getContent()).thenReturn(new ByteArrayInputStream(data.getBytes()));
        Mockito.when(httpResponse.getEntity()).thenReturn(entity);
        Mockito.when(httpClient.execute(Mockito.any(HttpPost.class))).thenReturn(httpResponse);

        HttpDriver httpDriver = new HttpDriver.Builder("", null, "asdf".toCharArray(), null, null)
                .build();
        httpDriver.setHttpClient(httpClient);

        List<NameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("data", "value"));

        String url = "https://localhost:4443/sample";

        String out = httpDriver.doPost(url, params);
        Assert.assertEquals(out, data);
    }

    @Test
    public void testDoPost404() throws IOException {
        CloseableHttpClient httpClient = Mockito.mock(CloseableHttpClient.class);
        CloseableHttpResponse httpResponse = Mockito.mock(CloseableHttpResponse.class);
        HttpEntity entity = Mockito.mock(HttpEntity.class);

        String data = "Not Found";

        Mockito.when(httpResponse.getStatusLine()).thenReturn(new BasicStatusLine(HttpVersion.HTTP_1_1, HttpStatus.SC_NOT_FOUND, "Not Found" ));
        Mockito.when(entity.getContent()).thenReturn(new ByteArrayInputStream(data.getBytes()));
        Mockito.when(httpResponse.getEntity()).thenReturn(entity);
        Mockito.when(httpClient.execute(Mockito.any(HttpPost.class))).thenReturn(httpResponse);

        HttpDriver httpDriver = new HttpDriver.Builder("", null, "asdf".toCharArray(), null, null)
                .build();
        httpDriver.setHttpClient(httpClient);

        List<NameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("data", "value"));

        String url = "https://localhost:4443/sample";

        String out = httpDriver.doPost(url, params);
        Assert.assertEquals(out, "");
    }

    @Test
    public void testDoPostException() throws IOException {
        CloseableHttpClient httpClient = Mockito.mock(CloseableHttpClient.class);

        Mockito.when(httpClient.execute(Mockito.any(HttpPost.class))).thenThrow(new IOException("Unknown error"));

        HttpDriver httpDriver = new HttpDriver.Builder("", null, "asdf".toCharArray(), null, null)
                .build();
        httpDriver.setHttpClient(httpClient);

        List<NameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("data", "value"));

        String url = "https://localhost:4443/sample";
        try {
            httpDriver.doPost(url, params);
        } catch (IOException e) {
            Mockito.verify(httpClient, Mockito.times(2)).execute(Mockito.any(HttpPost.class));
        }
    }

    @Test
    public void testDoPostExecuteNullResponse() throws IOException {
        CloseableHttpClient httpClient = Mockito.mock(CloseableHttpClient.class);
        Mockito.when(httpClient.execute(Mockito.any(HttpPost.class))).thenReturn(null);

        HttpDriver httpDriver = new HttpDriver.Builder("", null, "asdf".toCharArray(), null, null)
                .build();
        httpDriver.setHttpClient(httpClient);

        List<NameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("data", "value"));

        String url = "https://localhost:4443/sample";
        try {
            httpDriver.doPost(url, params);
        } catch (IOException e) {
            Mockito.verify(httpClient, Mockito.times(2)).execute(Mockito.any(HttpPost.class));
        }
    }

    @Test
    public void testClose() throws IOException {
        CloseableHttpClient httpClient = Mockito.mock(CloseableHttpClient.class);
        HttpDriver httpDriver = new HttpDriver.Builder("", null, "asdf".toCharArray(), null, null)
                .build();
        httpDriver.setHttpClient(httpClient);
        httpDriver.close();

        httpDriver.setHttpClient(null);
        httpDriver.close();
    }
}

