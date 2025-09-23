/*
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.msd;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class AthenzDependencyRequestTest {

    @Test
    public void testAthenzDependencyRequestFields() {
        AthenzDependencyRequest req1 = new AthenzDependencyRequest();
        req1.setDomainName("domain1");
        req1.setObjectName("svc1");
        req1.setObjectType(AthenzEntityType.service);
        req1.setOperation(AthenzEntityAction.create);
        req1.setPrincipal("p123");
        req1.setProvider("athenz");

        assertNotNull(req1);
        assertFalse(req1.equals(new Object()));
        assertEquals(req1.getDomainName(), "domain1");
        assertEquals(req1.getObjectName(), "svc1");
        assertEquals(req1.getObjectType(), AthenzEntityType.service);
        assertEquals(req1.getOperation(), AthenzEntityAction.create);
        assertEquals(req1.getPrincipal(), "p123");
        assertEquals(req1.getProvider(), "athenz");
        assertFalse(req1.equals(null));
        assertFalse(req1.equals(new Object()));
    }

    @Test(dataProvider = "dataForTestAthenzDependencyRequestEquality")
    public void testAthenzDependencyRequestEquality(AthenzDependencyRequest req1, AthenzDependencyRequest req2,
                                                    boolean expected) {
        assertEquals(req1.equals(req2), expected);
    }

    @DataProvider
    private Object[][] dataForTestAthenzDependencyRequestEquality() {
        AthenzDependencyRequest req1 = new AthenzDependencyRequest();
        req1.setDomainName("domain1");
        req1.setObjectName("svc1");
        req1.setObjectType(AthenzEntityType.service);
        req1.setOperation(AthenzEntityAction.create);
        req1.setPrincipal("p123");
        req1.setProvider("athenz");

        AthenzDependencyRequest req2 = new AthenzDependencyRequest();
        req2.setDomainName("domain1");
        req2.setObjectName("svc1");
        req2.setObjectType(AthenzEntityType.service);
        req2.setOperation(AthenzEntityAction.create);
        req2.setPrincipal("p123");
        req2.setProvider("athenz");

        AthenzDependencyRequest req3 = new AthenzDependencyRequest();
        req3.setDomainName("domain2");
        req3.setObjectName("svc1");
        req3.setObjectType(AthenzEntityType.service);
        req3.setOperation(AthenzEntityAction.create);
        req3.setPrincipal("p123");
        req3.setProvider("athenz");

        AthenzDependencyRequest req4 = new AthenzDependencyRequest();
        req4.setDomainName("domain1");
        req4.setObjectName("svc2");
        req4.setObjectType(AthenzEntityType.service);
        req4.setOperation(AthenzEntityAction.create);
        req4.setPrincipal("p123");
        req4.setProvider("athenz");

        AthenzDependencyRequest req5 = new AthenzDependencyRequest();
        req5.setDomainName("domain1");
        req5.setObjectName("svc1");
        req5.setObjectType(AthenzEntityType.role);
        req5.setOperation(AthenzEntityAction.create);
        req5.setPrincipal("p123");
        req5.setProvider("athenz");

        AthenzDependencyRequest req6 = new AthenzDependencyRequest();
        req6.setDomainName("domain1");
        req6.setObjectName("svc1");
        req6.setObjectType(AthenzEntityType.service);
        req6.setOperation(AthenzEntityAction.update);
        req6.setPrincipal("p123");
        req6.setProvider("athenz");

        AthenzDependencyRequest req7 = new AthenzDependencyRequest();
        req7.setDomainName("domain1");
        req7.setObjectName("svc1");
        req7.setObjectType(AthenzEntityType.service);
        req7.setOperation(AthenzEntityAction.create);
        req7.setPrincipal("p124");
        req7.setProvider("athenz");

        AthenzDependencyRequest req8 = new AthenzDependencyRequest();
        req8.setDomainName("domain1");
        req8.setObjectName("svc1");
        req8.setObjectType(AthenzEntityType.service);
        req8.setOperation(AthenzEntityAction.create);
        req8.setPrincipal("p123");
        req8.setProvider("msd");

        return new Object[][]{
            {req1, req1, true},
            {req1, req2, true},
            {req1, req3, false},
            {req1, req4, false},
            {req1, req5, false},
            {req1, req6, false},
            {req1, req7, false},
            {req1, req8, false},
            {new AthenzDependencyRequest(), new AthenzDependencyRequest(), true}
            };
    }
}