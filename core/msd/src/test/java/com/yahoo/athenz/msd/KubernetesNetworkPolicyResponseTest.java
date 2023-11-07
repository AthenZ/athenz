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

package com.yahoo.athenz.msd;
import org.testng.annotations.Test;

import java.util.HashMap;

import static org.testng.Assert.*;

public class KubernetesNetworkPolicyResponseTest {

    @Test
    public void testMethods() {
        KubernetesNetworkPolicyResponse knp = new KubernetesNetworkPolicyResponse();
        knp.setApiVersion("apiVersion");
        knp.setKind("kind");
        knp.setMetadata(null);
        knp.setSpec(null);
        assertEquals(knp.getApiVersion(), "apiVersion");
        assertEquals(knp.getKind(), "kind");
        assertNull(knp.getMetadata());
        assertNull(knp.getSpec());

        KubernetesNetworkPolicyResponse knp2 = new KubernetesNetworkPolicyResponse();
        knp2.setApiVersion("apiVersion");
        knp2.setKind("kind");
        knp2.setMetadata(null);
        knp2.setSpec(null);

        assertEquals(knp, knp2);
        assertFalse(knp.equals("abc"));

        knp2.setApiVersion("apiVersion2");
        assertNotEquals(knp, knp2);

        knp2.setApiVersion("apiVersion");
        knp2.setKind("kind2");
        assertNotEquals(knp, knp2);

        knp2.setKind("kind");
        knp2.setMetadata(new HashMap<>());
        assertNotEquals(knp, knp2);

        knp2.setMetadata(null);
        knp2.setSpec(new KubernetesNetworkPolicySpec());
        assertNotEquals(knp, knp2);
    }
}