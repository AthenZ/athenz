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

import com.yahoo.rdl.Schema;
import com.yahoo.rdl.Validator;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.List;

import static org.testng.Assert.*;

public class RoleCertificateTest {

    @Test
    public void testRoleCertificateRequest() {

        RoleCertificate data1 = new RoleCertificate();
        data1.setX509Certificate("x509cert");

        RoleCertificate data2 = new RoleCertificate();
        data2.setX509Certificate("x509cert");

        assertEquals(data1, data1);
        assertEquals(data1, data2);

        // verify getters
        assertEquals("x509cert", data2.getX509Certificate());

        data1.setX509Certificate("x509cert1");
        assertNotEquals(data2, data1);
        data1.setX509Certificate(null);
        assertNotEquals(data2, data1);

        assertNotEquals(data1, null);
        assertNotEquals("data", data2);
    }

    @Test
    public void testRoleCertificateRequireRoleCert() {
        Schema schema = ZTSSchema.instance();
        Validator validator = new Validator(schema);

        List<String> roles1 = new ArrayList<>();
        roles1.add("role1");
        roles1.add("role2");
        RoleAccess roleList1 = new RoleAccess();
        roleList1.setRoles(roles1);

        Validator.Result result = validator.validate(roleList1, "RoleAccess");
        assertTrue(result.valid);

        List<String> roles2 = new ArrayList<>();
        roles2.add("role1");
        roles2.add("role2");
        RoleAccess roleList2 = new RoleAccess();
        roleList2.setRoles(roles2);
        assertTrue(roleList1.equals(roleList1));
        assertTrue(roleList1.equals(roleList2));

        assertTrue(roleList1.getRoles().equals(roleList2.getRoles()));

        roles1.remove("role1");
        assertFalse(roleList1.equals(roleList2));

        roles2.remove("role1");
        assertTrue(roleList1.equals(roleList2));

        roleList1.setRoles(new ArrayList<>());
        assertFalse(roleList1.equals(roleList2));
        roleList2.setRoles(new ArrayList<>());
        assertTrue(roleList1.equals(roleList2));

        roleList1.setRoles(null);
        assertFalse(roleList1.equals(roleList2));
        roleList2.setRoles(null);
        assertTrue(roleList1.equals(roleList2));

        assertFalse(roleList1.equals(null));
        assertFalse(roleList1.equals(new Object()));
    }
}
