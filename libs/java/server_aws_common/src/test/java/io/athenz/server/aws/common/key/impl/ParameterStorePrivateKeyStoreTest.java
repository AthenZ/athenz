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

package io.athenz.server.aws.common.key.impl;

import com.yahoo.athenz.auth.PrivateKeyStore;
import org.mockito.Mockito;
import org.testng.annotations.Test;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.model.GetParameterResponse;
import software.amazon.awssdk.services.ssm.model.Parameter;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.function.Consumer;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.testng.Assert.*;

public class ParameterStorePrivateKeyStoreTest {

    private ParameterStorePrivateKeyStoreFactory getFactory(final SsmClient ssmClient) {
        return new ParameterStorePrivateKeyStoreFactory() {
            @Override
            public PrivateKeyStore create() {
                return new ParameterStorePrivateKeyStore(ssmClient);
            }
        };
    }

    @Test
   public void testGetSecret() {
        SsmClient ssmClient = Mockito.mock(SsmClient.class);
        when(ssmClient.getParameter(any(Consumer.class)))
                .thenReturn(GetParameterResponse.builder().parameter(Parameter.builder().value("secret").build()).build());
        ParameterStorePrivateKeyStore store = (ParameterStorePrivateKeyStore)getFactory(ssmClient).create();
        assertEquals(store.getSecret("app1", null, "key1"), "secret".toCharArray());
    }

    @Test
    public void testGetPrivateKey() throws IOException {
        SsmClient ssmClient = Mockito.mock(SsmClient.class);
        Path path = Paths.get("src/test/resources/unit_test_ec_private.key");
        try (FileInputStream fis = new FileInputStream(path.toFile())) {
            String secret = new String(fis.readAllBytes());
            when(ssmClient.getParameter(any(Consumer.class)))
                    .thenReturn(GetParameterResponse.builder().parameter(Parameter.builder().value(secret).build()).build());
            ParameterStorePrivateKeyStore store = (ParameterStorePrivateKeyStore)getFactory(ssmClient).create();
            assertNotNull(store.getPrivateKey("zms", "host1", "region1", "EC"));
        }
    }

    @Test
    public void testGetPrivateKeyInvalidInputs() {
        SsmClient ssmClient = Mockito.mock(SsmClient.class);
        ParameterStorePrivateKeyStore store = (ParameterStorePrivateKeyStore)getFactory(ssmClient).create();
        assertNull(store.getPrivateKey("unknown", "host1", "region1", "EC"));
        assertNull(store.getPrivateKey("zms", "host1", "region1", "unknown"));
        assertNull(store.getPrivateKey("zms", "host1", null, "RSA"));
    }
}