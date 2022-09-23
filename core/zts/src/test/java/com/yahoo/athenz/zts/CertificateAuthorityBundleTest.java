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

package com.yahoo.athenz.zts;

import org.testng.annotations.Test;
import static org.testng.Assert.*;

public class CertificateAuthorityBundleTest {

    @Test
    public void testCertificateAuthorityBundle() {

        CertificateAuthorityBundle bundle1 = new CertificateAuthorityBundle()
                .setCerts("certs").setName("athenz");

        assertEquals(bundle1.getCerts(), "certs");
        assertEquals(bundle1.getName(), "athenz");

        CertificateAuthorityBundle bundle2 = new CertificateAuthorityBundle()
                .setCerts("certs").setName("athenz");

        assertEquals(bundle2, bundle1);
        assertEquals(bundle1, bundle1);
        assertFalse(bundle2.equals("text"));

        bundle1.setCerts("certs2");
        assertNotEquals(bundle2, bundle1);
        bundle1.setCerts(null);
        assertNotEquals(bundle2, bundle1);
        bundle1.setCerts("certs");
        assertEquals(bundle2, bundle1);

        bundle1.setName("athenz2");
        assertNotEquals(bundle2, bundle1);
        bundle1.setName(null);
        assertNotEquals(bundle2, bundle1);
        bundle1.setName("athenz");
        assertEquals(bundle2, bundle1);
    }
}
