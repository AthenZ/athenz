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

import com.yahoo.rdl.Schema;
import com.yahoo.rdl.Validator;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.testng.Assert.*;

public class WorkloadRequestsTest {
    @Test
    public void testWorkloadRequestsFields() {
        WorkloadRequests wl1 = new WorkloadRequests();
        List<WorkloadRequest> requestList = new ArrayList<>();
        requestList.add(new WorkloadRequest().setDomainName("athenz").setServiceNames(Arrays.asList("api")));
        wl1.setApplicableStaticTypes(Arrays.asList(StaticWorkloadType.VIP_LB));
        wl1.setWorkloadRequest(requestList);
        wl1.init();

        assertNotNull(wl1);
        assertTrue(wl1.getFetchDynamicTypeWorkloads());
        assertTrue(wl1.getFetchStaticTypeWorkloads());
        assertFalse(wl1.getResolveStaticWorkloads());
        assertNotNull(wl1.getApplicableStaticTypes());
        assertNotNull(wl1.getWorkloadRequest());
        assertFalse(wl1.equals(new Object()));
        assertEquals(wl1.getWorkloadRequest().get(0).getDomainName(), "athenz");
        assertEquals(wl1.getWorkloadRequest().get(0).getServiceNames().get(0), "api");
        assertFalse(wl1.getWorkloadRequest().get(0).equals(new Object()));
    }

    @Test (dataProvider = "WorkloadRequestsProviderForEqualityCheck")
    public void testWorkloadRequestsEquality(WorkloadRequests wl1, WorkloadRequests wl2, boolean expected) {
    	assertEquals(wl1.equals(wl2), expected);
    }

    @DataProvider
    private Object[][] WorkloadRequestsProviderForEqualityCheck() {
        WorkloadRequests wl1 = new WorkloadRequests();
        List<WorkloadRequest> requestList = new ArrayList<>();
        requestList.add(new WorkloadRequest().setDomainName("athenz").setServiceNames(Arrays.asList("api")));
        wl1.setApplicableStaticTypes(Arrays.asList(StaticWorkloadType.VIP_LB));
        wl1.init();
        wl1.setWorkloadRequest(requestList);

        WorkloadRequests wl2 = new WorkloadRequests();
        requestList = new ArrayList<>();
        requestList.add(new WorkloadRequest().setDomainName("athenz").setServiceNames(Arrays.asList("api")));
        wl2.setApplicableStaticTypes(Arrays.asList(StaticWorkloadType.VIP_LB));
        wl2.setFetchDynamicTypeWorkloads(true);
        wl2.setFetchStaticTypeWorkloads(true);
        wl2.setResolveStaticWorkloads(false);
        wl2.setWorkloadRequest(requestList);

        WorkloadRequests wl3 = new WorkloadRequests();
        requestList = new ArrayList<>();
        requestList.add(new WorkloadRequest().setDomainName("athenz").setServiceNames(Arrays.asList("api")));
        wl3.setApplicableStaticTypes(Arrays.asList(StaticWorkloadType.VIP_LB));
        wl3.setFetchDynamicTypeWorkloads(true);
        wl3.setFetchStaticTypeWorkloads(true);
        wl3.setResolveStaticWorkloads(true);
        wl3.setWorkloadRequest(requestList);

        WorkloadRequests wl4 = new WorkloadRequests();
        requestList = new ArrayList<>();
        requestList.add(new WorkloadRequest().setDomainName("athenz").setServiceNames(Arrays.asList("api")));
        wl4.setApplicableStaticTypes(Arrays.asList(StaticWorkloadType.VIP_LB));
        wl4.setFetchDynamicTypeWorkloads(true);
        wl4.setFetchStaticTypeWorkloads(false);
        wl4.setResolveStaticWorkloads(false);
        wl4.setWorkloadRequest(requestList);

        WorkloadRequests wl5 = new WorkloadRequests();
        requestList = new ArrayList<>();
        requestList.add(new WorkloadRequest().setDomainName("athenz").setServiceNames(Arrays.asList("api")));
        wl5.setApplicableStaticTypes(Arrays.asList(StaticWorkloadType.VIP_LB));
        wl5.setFetchDynamicTypeWorkloads(false);
        wl5.setFetchStaticTypeWorkloads(true);
        wl5.setResolveStaticWorkloads(false);
        wl5.setWorkloadRequest(requestList);

        WorkloadRequests wl6 = new WorkloadRequests();
        requestList = new ArrayList<>();
        requestList.add(new WorkloadRequest().setDomainName("athenz").setServiceNames(Arrays.asList("api")));
        wl6.setApplicableStaticTypes(Arrays.asList(StaticWorkloadType.VIP));
        wl6.setFetchDynamicTypeWorkloads(true);
        wl6.setFetchStaticTypeWorkloads(true);
        wl6.setResolveStaticWorkloads(false);
        wl6.setWorkloadRequest(requestList);

        WorkloadRequests wl7 = new WorkloadRequests();
        requestList = new ArrayList<>();
        requestList.add(new WorkloadRequest().setDomainName("athenz").setServiceNames(Arrays.asList("msd")));
        wl7.setApplicableStaticTypes(Arrays.asList(StaticWorkloadType.VIP_LB));
        wl7.setFetchDynamicTypeWorkloads(true);
        wl7.setFetchStaticTypeWorkloads(true);
        wl7.setResolveStaticWorkloads(false);
        wl7.setWorkloadRequest(requestList);

        return new Object[][] {
                {wl1, wl2, true},
                {wl1, wl3, false},
                {wl1, wl4, false},
                {wl1, wl5, false},
                {wl1, wl6, false},
                {wl1, wl7, false},
        };
    }

    @Test (dataProvider = "WorkloadRequestProviderForEqualityCheck")
    public void testWorkloadRequestEquality(WorkloadRequest wl1, WorkloadRequest wl2, boolean expected) {
    	assertEquals(wl1.equals(wl2), expected);
    }

    @DataProvider
    private Object[][] WorkloadRequestProviderForEqualityCheck() {
        WorkloadRequest wl1 = new WorkloadRequest();
        wl1.setDomainName("athenz");
        wl1.setServiceNames(Arrays.asList("api"));

        WorkloadRequest wl2 = new WorkloadRequest();
        wl2.setDomainName("athenz");
        wl2.setServiceNames(Arrays.asList("api"));

        WorkloadRequest wl3 = new WorkloadRequest();
        wl3.setDomainName("athenz");
        wl3.setServiceNames(Arrays.asList("msd"));

        WorkloadRequest wl4 = new WorkloadRequest();
        wl4.setDomainName("athenz-msd");
        wl4.setServiceNames(Arrays.asList("api"));

        return new Object[][] {
                {wl1, wl2, true},
                {wl1, wl3, false},
                {wl1, wl4, false},
        };
    }

    @Test (dataProvider = "WorkloadRequestsProvider")
    public void testWorkloadRequestsName(WorkloadRequests wl1, boolean expected) {

        Schema schema = MSDSchema.instance();
        Validator validator = new Validator(schema);
        Validator.Result result = validator.validate(wl1, "WorkloadRequests");
        assertEquals(result.valid, expected);
    }

    @DataProvider
    private Object[][] WorkloadRequestsProvider() {
        WorkloadRequests wl1 = new WorkloadRequests();
        List<WorkloadRequest> requestList = new ArrayList<>();
        requestList.add(new WorkloadRequest().setDomainName("athenz").setServiceNames(Arrays.asList("api")));
        wl1.setApplicableStaticTypes(Arrays.asList(StaticWorkloadType.VIP_LB));
        wl1.setFetchDynamicTypeWorkloads(true);
        wl1.setFetchStaticTypeWorkloads(false);
        wl1.setResolveStaticWorkloads(true);
        wl1.setWorkloadRequest(requestList);

    	return new Object[][] {
                {wl1, true},
        };
    }
}