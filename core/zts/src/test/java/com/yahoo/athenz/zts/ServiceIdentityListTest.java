/*
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

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.testng.annotations.Test;

@SuppressWarnings({"ALL", "EqualsWithItself"})
public class ServiceIdentityListTest {

    @Test
    public void testServiceIdentityList() {
        ServiceIdentityList sil = new ServiceIdentityList();
        ServiceIdentityList sil2 = new ServiceIdentityList();

        List<String> nl = new ArrayList<String>();
        nl.add("sample.service1");

        sil.setNames(nl);
        assertEquals(sil.getNames(), nl);

        assertTrue(sil.equals(sil));
        //noinspection ObjectEqualsNull,ConstantConditions
        assertFalse(sil.equals(null));
        assertFalse(sil.equals(sil2));
    }
}
