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

import java.util.Collections;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;

public class TenantDomainsTest {

    @Test
    public void TestTenantDomainNames() {
        
        TenantDomains td1 = new TenantDomains();
        TenantDomains td2 = new TenantDomains();

        td1.setTenantDomainNames(Collections.singletonList("domain1"));
        td2.setTenantDomainNames(Collections.singletonList("domain1"));

        assertEquals(Collections.singletonList("domain1"), td1.getTenantDomainNames());

        assertEquals(td1, td2);
        assertEquals(td1, td1);

        td1.setTenantDomainNames(Collections.singletonList("domain2"));
        assertNotEquals(td2, td1);
        td1.setTenantDomainNames(null);
        assertNotEquals(td2, td1);
        td1.setTenantDomainNames(Collections.singletonList("domain1"));
        assertEquals(td2, td1);

        assertNotEquals(td2, null);
        assertNotEquals("td2", td1);
    }

}
