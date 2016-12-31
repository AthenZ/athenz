/**
 * Copyright 2016 Yahoo Inc.
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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.testng.Assert;
import org.testng.annotations.Test;

public class TenantDomainsTest {

    @Test
    public void TestsetgetTenantDomainNames() {
        TenantDomains td = new TenantDomains();

        List<String> list = new ArrayList<String>(Arrays.asList("A", "B", "C"));

        td.setTenantDomainNames(list);

        Assert.assertEquals(td.getTenantDomainNames(), list);
    }

    @Test
    public void TestEqualsTrue() {
        TenantDomains td = new TenantDomains();
        td.equals(td);
    }

    @Test
    public void TestEqualsFalse() {
        TenantDomains td1 = new TenantDomains();
        TenantDomains td2 = new TenantDomains();

        td1.setTenantDomainNames(new ArrayList<String>(Arrays.asList("A", "B", "C")));

        Assert.assertFalse(td1.equals(td2));
        Assert.assertFalse(td1.equals(new String()));
    }

}
