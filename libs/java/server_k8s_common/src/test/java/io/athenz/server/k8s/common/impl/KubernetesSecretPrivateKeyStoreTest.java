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
package io.athenz.server.k8s.common.impl;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.auth.ServerPrivateKey;
import io.kubernetes.client.openapi.ApiClient;
import okhttp3.HttpUrl;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;

import java.io.FileInputStream;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.testng.Assert.*;

public class KubernetesSecretPrivateKeyStoreTest {
    private KubernetesSecretPrivateKeyStoreFactory getFactory(final ApiClient k8sClient) {
        return new KubernetesSecretPrivateKeyStoreFactory() {
            @Override
            public PrivateKeyStore create() {
                return new KubernetesSecretPrivateKeyStore(k8sClient);
            }
        };
    }

    private MockWebServer server;

    @Test
    public void testGetSecret() throws Exception {
        server = new MockWebServer();
        Path path = Paths.get("src/test/resources/sample-secret-response.json");
        try (FileInputStream fis = new FileInputStream(path.toFile())) {
            server.enqueue(new MockResponse().setBody(new String(fis.readAllBytes())));
            server.start();
            ApiClient k8sClient = Mockito.spy(new ApiClient());
            HttpUrl baseUrl = server.url("/api/v1/namespaces/myns/secrets/mysecret");
            k8sClient.setBasePath(baseUrl.toString());
            KubernetesSecretPrivateKeyStoreFactory factory = getFactory(k8sClient);
            assertEquals(factory.create().getSecret("myns", "mysecret", "password"), new char[]{'c', 'h', 'a', 'n', 'g', 'e', 'i', 't'});
        }
    }

    @Test
    public void testGetSecretMissing() throws Exception {
        server = new MockWebServer();
        Path path = Paths.get("src/test/resources/invalid-secret-key-response.json");
        try (FileInputStream fis = new FileInputStream(path.toFile())) {
            server.enqueue(new MockResponse().setBody(new String(fis.readAllBytes())));
            server.start();
            ApiClient k8sClient = Mockito.spy(new ApiClient());
            HttpUrl baseUrl = server.url("/api/v1/namespaces/myns/secrets/mysecret");
            k8sClient.setBasePath(baseUrl.toString());
            KubernetesSecretPrivateKeyStoreFactory factory = getFactory(k8sClient);
            assertEquals(factory.create().getSecret("myns", "mysecret", "password"), new char[]{});
        }
    }

    @Test
    public void testGetPrivateKey() throws Exception {
        server = new MockWebServer();
        Path path = Paths.get("src/test/resources/sample-secret-key-response.json");
        byte[] keyBytes;
        try (FileInputStream fis = new FileInputStream(path.toFile())) {
            keyBytes = fis.readAllBytes();
            //mock response for zms key
            server.enqueue(new MockResponse().setBody(new String(keyBytes)));
            //mock response for zms key id
            server.enqueue(new MockResponse().setBody(new String(keyBytes)));
            //mock response for zts key
            server.enqueue(new MockResponse().setBody(new String(keyBytes)));
            //mock response for zts key id
            server.enqueue(new MockResponse().setBody(new String(keyBytes)));
            //mock response for msd key
            server.enqueue(new MockResponse().setBody(new String(keyBytes)));
            //mock response for msd key id
            server.enqueue(new MockResponse().setBody(new String(keyBytes)));
            server.start();
            ApiClient k8sClient = Mockito.spy(new ApiClient());
            HttpUrl baseUrl = server.url("/api/v1/namespaces/myns/secrets/mysecret");
            k8sClient.setBasePath(baseUrl.toString());
            KubernetesSecretPrivateKeyStoreFactory factory = getFactory(k8sClient);
            KubernetesSecretPrivateKeyStore store = (KubernetesSecretPrivateKeyStore) factory.create();
            assertNotNull(store.getPrivateKey("zms", "myns","mysecret", "EC"));
            assertNotNull(store.getPrivateKey("zts", "myns","mysecret", "EC"));
            assertNotNull(store.getPrivateKey("msd", "myns","mysecret", "EC"));
            // no mock response present so expected a read timeout
            assertNull(store.getPrivateKey("msd", "myns","mysecret", "EC"));
            assertNull(store.getPrivateKey("unknown", "myns","mysecret", "EC"));
        }
    }

    @AfterMethod
    public void tearDown() throws Exception {
        server.shutdown();
    }
}