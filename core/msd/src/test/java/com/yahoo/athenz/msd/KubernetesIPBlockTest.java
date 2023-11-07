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

import java.util.List;

import static org.testng.Assert.*;

public class KubernetesIPBlockTest {

    @Test
    public void testMethods() {
        KubernetesIPBlock kubernetesIPBlock1 = new KubernetesIPBlock();
        kubernetesIPBlock1.setCidr("10.0.0.0/12");
        kubernetesIPBlock1.setExcept(null);
        assertEquals(kubernetesIPBlock1.getCidr(), "10.0.0.0/12");
        assertNull(kubernetesIPBlock1.getExcept());
        KubernetesIPBlock kubernetesIPBlock2 = new KubernetesIPBlock();
        kubernetesIPBlock2.setCidr("10.0.0.0/12");
        kubernetesIPBlock2.setExcept(null);

        assertEquals(kubernetesIPBlock1, kubernetesIPBlock2);
        assertFalse(kubernetesIPBlock1.equals("abc"));

        kubernetesIPBlock2.setCidr("10.0.0.0/13");
        assertNotEquals(kubernetesIPBlock1, kubernetesIPBlock2);

        kubernetesIPBlock2.setCidr("10.0.0.0/12");
        kubernetesIPBlock2.setExcept(List.of("10.0.0.2"));
        assertNotEquals(kubernetesIPBlock1, kubernetesIPBlock2);
    }
}