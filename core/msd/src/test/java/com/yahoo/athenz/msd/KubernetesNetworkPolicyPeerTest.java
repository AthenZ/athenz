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

import static org.testng.Assert.*;

public class KubernetesNetworkPolicyPeerTest {

    @Test
    public void testMethods() {
        KubernetesNetworkPolicyPeer peer1 = new KubernetesNetworkPolicyPeer();
        KubernetesIPBlock ipBlock = new KubernetesIPBlock();
        KubernetesLabelSelector podSelector = new KubernetesLabelSelector();
        KubernetesLabelSelector namespaceSelector = new KubernetesLabelSelector();
        peer1.setIpBlock(ipBlock);
        peer1.setNamespaceSelector(namespaceSelector);
        peer1.setPodSelector(podSelector);
        assertEquals(peer1.getIpBlock(), ipBlock);
        assertEquals(peer1.getNamespaceSelector(), namespaceSelector);
        assertEquals(peer1.getPodSelector(), podSelector);

        KubernetesNetworkPolicyPeer peer2 = new KubernetesNetworkPolicyPeer();
        peer2.setIpBlock(ipBlock);
        peer2.setNamespaceSelector(namespaceSelector);
        peer2.setPodSelector(podSelector);

        assertEquals(peer1, peer2);
        assertFalse(peer1.equals("abc"));

        peer2.setIpBlock(null);
        assertNotEquals(peer1, peer2);

        peer2.setIpBlock(ipBlock);
        peer2.setPodSelector(null);
        assertNotEquals(peer1, peer2);

        peer2.setPodSelector(podSelector);
        peer2.setNamespaceSelector(null);
        assertNotEquals(peer1, peer2);
    }
}