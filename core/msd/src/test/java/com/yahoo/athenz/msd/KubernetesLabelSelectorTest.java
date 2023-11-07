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
import java.util.List;

import static org.testng.Assert.*;

public class KubernetesLabelSelectorTest {
    @Test
    public void testMethods() {
        KubernetesLabelSelector kubernetesLabelSelector1 = new KubernetesLabelSelector();
        kubernetesLabelSelector1.setMatchExpressions(null);
        kubernetesLabelSelector1.setMatchLabels(null);
        assertNull(kubernetesLabelSelector1.getMatchExpressions());
        assertNull(kubernetesLabelSelector1.getMatchLabels());

        KubernetesLabelSelector kubernetesLabelSelector2 = new KubernetesLabelSelector();
        kubernetesLabelSelector2.setMatchExpressions(null);
        kubernetesLabelSelector2.setMatchLabels(null);

        assertEquals(kubernetesLabelSelector1, kubernetesLabelSelector2);
        assertFalse(kubernetesLabelSelector1.equals("abc"));

        KubernetesLabelSelectorRequirement labelSelectorRequirement = new KubernetesLabelSelectorRequirement();
        kubernetesLabelSelector2.setMatchExpressions(List.of(labelSelectorRequirement));
        assertNotEquals(kubernetesLabelSelector1, kubernetesLabelSelector2);

        kubernetesLabelSelector2.setMatchExpressions(null);
        kubernetesLabelSelector2.setMatchLabels(new HashMap<>());
        assertNotEquals(kubernetesLabelSelector1, kubernetesLabelSelector2);
    }
}