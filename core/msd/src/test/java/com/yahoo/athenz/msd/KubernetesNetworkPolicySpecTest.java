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

import java.util.ArrayList;

import static org.testng.Assert.*;

public class KubernetesNetworkPolicySpecTest {

    @Test
    public void testMethods() {
        KubernetesNetworkPolicySpec spec1 = new KubernetesNetworkPolicySpec();
        spec1.setEgress(null);
        spec1.setIngress(null);
        spec1.setPodSelector(null);
        spec1.setPolicyTypes(null);
        assertNull(spec1.getEgress());
        assertNull(spec1.getIngress());
        assertNull(spec1.getPodSelector());
        assertNull(spec1.getPolicyTypes());

        KubernetesNetworkPolicySpec spec2 = new KubernetesNetworkPolicySpec();
        spec2.setEgress(null);
        spec2.setIngress(null);
        spec2.setPodSelector(null);
        spec2.setPolicyTypes(null);

        assertEquals(spec1, spec2);
        assertFalse(spec1.equals("abc"));

        spec2.setEgress(new ArrayList<>());
        assertNotEquals(spec1, spec2);

        spec2.setEgress(null);
        spec2.setIngress(new ArrayList<>());
        assertNotEquals(spec1, spec2);

        spec2.setIngress(null);
        spec2.setPodSelector(new KubernetesLabelSelector());
        assertNotEquals(spec1, spec2);

        spec2.setPodSelector(null);
        spec2.setPolicyTypes(new ArrayList<>());
        assertNotEquals(spec1, spec2);
    }
}