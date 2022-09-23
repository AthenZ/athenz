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

import java.util.Arrays;
import java.util.List;

import org.testng.Assert;
import org.testng.annotations.Test;

@SuppressWarnings("EqualsWithItself")
public class RoleAccessTest {

    @Test
    public void TestsetgetRoleAccess() {

        List<String> roles = Arrays.asList("role1", "role2", "role3");
        RoleAccess ra = new RoleAccess().setRoles(roles);

        Assert.assertEquals(ra.getRoles(), roles);
    }

    @Test
    public void TestEqualsTrue() {
        RoleAccess ra = new RoleAccess();
        //noinspection ResultOfMethodCallIgnored
        ra.equals(ra);
    }

    @Test
    public void TestEqualsFalse() {
        RoleAccess ra1 = new RoleAccess();
        RoleAccess ra2 = new RoleAccess();

        List<String> roles = Arrays.asList("role1", "role2", "role3");
        ra1.setRoles(roles);
        Assert.assertNotEquals(ra1, ra2);
        //noinspection EqualsBetweenInconvertibleTypes
        Assert.assertNotEquals("", ra1);
    }

}
