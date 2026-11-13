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
package com.yahoo.athenz.zms;

import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.util.Collections;

import static org.testng.Assert.*;

public class ZMSClientPolicyBundleTest {

    private static final String AUDIT_REF = "audit-ref";

    interface ClientCall {
        void call(ZMSClient client);
    }

    @Test
    public void testPolicyBundleApis() throws Exception {

        ZMSRDLGeneratedClient mockClient = Mockito.mock(ZMSRDLGeneratedClient.class);
        ZMSClient client = new ZMSClient("https://localhost:4443/zms/v1");
        client.setZMSRDLGeneratedClient(mockClient);

        PolicyBundle bundle = new PolicyBundle().setName("sports:bundle.api").setEngine("rego")
                .setFiles(Collections.singletonList(new PolicyBundleFile().setPath("authz.rego").setContent("package x")));
        PolicyBundleFile file = new PolicyBundleFile().setPath("data.json").setContent("{}");
        PolicyBundleOptions options = new PolicyBundleOptions().setVersion("1");
        PolicyBundleList list = new PolicyBundleList().setNames(Collections.singletonList("api"));
        PolicyBundles bundles = new PolicyBundles().setList(Collections.singletonList(bundle));

        Mockito.when(mockClient.getPolicyBundleList("sports")).thenReturn(list);
        Mockito.when(mockClient.getPolicyBundles("sports", true)).thenReturn(bundles);
        Mockito.when(mockClient.getPolicyBundle("sports", "api")).thenReturn(bundle);
        Mockito.when(mockClient.putPolicyBundle("sports", "api", AUDIT_REF, true, bundle)).thenReturn(bundle);
        Mockito.when(mockClient.getPolicyBundleVersionList("sports", "api")).thenReturn(list);
        Mockito.when(mockClient.getPolicyBundleVersion("sports", "api", "0")).thenReturn(bundle);
        Mockito.when(mockClient.putPolicyBundleVersion("sports", "api", options, AUDIT_REF, true)).thenReturn(bundle);

        assertEquals(client.getPolicyBundleList("sports"), list);
        assertEquals(client.getPolicyBundles("sports", true), bundles);
        assertEquals(client.getPolicyBundle("sports", "api"), bundle);
        assertEquals(client.putPolicyBundle("sports", "api", AUDIT_REF, true, bundle), bundle);
        client.deletePolicyBundle("sports", "api", AUDIT_REF);
        client.putPolicyBundleFile("sports", "api", AUDIT_REF, file);
        client.deletePolicyBundleFile("sports", "api", AUDIT_REF, "data.json");
        assertEquals(client.getPolicyBundleVersionList("sports", "api"), list);
        assertEquals(client.getPolicyBundleVersion("sports", "api", "0"), bundle);
        assertEquals(client.putPolicyBundleVersion("sports", "api", options, AUDIT_REF, true), bundle);
        client.setActivePolicyBundleVersion("sports", "api", options, AUDIT_REF);
        client.deletePolicyBundleVersion("sports", "api", "0", AUDIT_REF);

        Mockito.verify(mockClient).deletePolicyBundle("sports", "api", AUDIT_REF);
        Mockito.verify(mockClient).putPolicyBundleFile("sports", "api", AUDIT_REF, file);
        Mockito.verify(mockClient).deletePolicyBundleFile("sports", "api", "data.json", AUDIT_REF);
        Mockito.verify(mockClient).setActivePolicyBundleVersion("sports", "api", options, AUDIT_REF);
        Mockito.verify(mockClient).deletePolicyBundleVersion("sports", "api", "0", AUDIT_REF);
    }

    @Test
    public void testPolicyBundleApisFailures() throws Exception {

        ZMSRDLGeneratedClient mockClient = Mockito.mock(ZMSRDLGeneratedClient.class);
        ZMSClient client = new ZMSClient("https://localhost:4443/zms/v1");
        client.setZMSRDLGeneratedClient(mockClient);

        PolicyBundle bundle = new PolicyBundle().setName("sports:bundle.api");
        PolicyBundleFile file = new PolicyBundleFile().setPath("data.json");
        PolicyBundleOptions options = new PolicyBundleOptions().setVersion("1");

        for (Exception ex : new Exception[] { new ClientResourceException(403), new NullPointerException() }) {

            final int code = (ex instanceof ClientResourceException) ? 403 : 400;

            Mockito.reset(mockClient);
            Mockito.when(mockClient.getPolicyBundleList("sports")).thenThrow(ex);
            Mockito.when(mockClient.getPolicyBundles("sports", false)).thenThrow(ex);
            Mockito.when(mockClient.getPolicyBundle("sports", "api")).thenThrow(ex);
            Mockito.when(mockClient.putPolicyBundle("sports", "api", AUDIT_REF, false, bundle)).thenThrow(ex);
            Mockito.when(mockClient.deletePolicyBundle("sports", "api", AUDIT_REF)).thenThrow(ex);
            Mockito.when(mockClient.putPolicyBundleFile("sports", "api", AUDIT_REF, file)).thenThrow(ex);
            Mockito.when(mockClient.deletePolicyBundleFile("sports", "api", "data.json", AUDIT_REF)).thenThrow(ex);
            Mockito.when(mockClient.getPolicyBundleVersionList("sports", "api")).thenThrow(ex);
            Mockito.when(mockClient.getPolicyBundleVersion("sports", "api", "0")).thenThrow(ex);
            Mockito.when(mockClient.putPolicyBundleVersion("sports", "api", options, AUDIT_REF, false)).thenThrow(ex);
            Mockito.when(mockClient.setActivePolicyBundleVersion("sports", "api", options, AUDIT_REF)).thenThrow(ex);
            Mockito.when(mockClient.deletePolicyBundleVersion("sports", "api", "0", AUDIT_REF)).thenThrow(ex);

            ClientCall[] calls = new ClientCall[] {
                c -> c.getPolicyBundleList("sports"),
                c -> c.getPolicyBundles("sports", false),
                c -> c.getPolicyBundle("sports", "api"),
                c -> c.putPolicyBundle("sports", "api", AUDIT_REF, false, bundle),
                c -> c.deletePolicyBundle("sports", "api", AUDIT_REF),
                c -> c.putPolicyBundleFile("sports", "api", AUDIT_REF, file),
                c -> c.deletePolicyBundleFile("sports", "api", AUDIT_REF, "data.json"),
                c -> c.getPolicyBundleVersionList("sports", "api"),
                c -> c.getPolicyBundleVersion("sports", "api", "0"),
                c -> c.putPolicyBundleVersion("sports", "api", options, AUDIT_REF, false),
                c -> c.setActivePolicyBundleVersion("sports", "api", options, AUDIT_REF),
                c -> c.deletePolicyBundleVersion("sports", "api", "0", AUDIT_REF)
            };
            for (ClientCall call : calls) {
                try {
                    call.call(client);
                    fail();
                } catch (ZMSClientException zex) {
                    assertEquals(zex.getCode(), code);
                }
            }
        }
    }
}
