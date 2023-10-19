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
import static org.testng.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.yahoo.rdl.Schema;
import com.yahoo.rdl.Validator;

public class BulkWorkloadRequestTest {
	@Test
	public void testBulkWorkloadRequestFields() {
		BulkWorkloadRequest wl1 = new BulkWorkloadRequest();
		List<DomainServices> requestList = new ArrayList<>();
		requestList.add(new DomainServices().setDomainName("athenz").setServiceNames(Arrays.asList("api")));
		wl1.setApplicableStaticTypes(Arrays.asList(StaticWorkloadType.VIP_LB));
		wl1.setDomainServices(requestList);
		wl1.init();

		assertNotNull(wl1);
		assertTrue(wl1.getFetchDynamicTypeWorkloads());
		assertTrue(wl1.getFetchStaticTypeWorkloads());
		assertFalse(wl1.getResolveStaticWorkloads());
		assertNotNull(wl1.getApplicableStaticTypes());
		assertNotNull(wl1.getDomainServices());
		assertFalse(wl1.equals(new Object()));
		assertEquals(wl1.getDomainServices().get(0).getDomainName(), "athenz");
		assertEquals(wl1.getDomainServices().get(0).getServiceNames().get(0), "api");
		assertFalse(wl1.getDomainServices().get(0).equals(new Object()));
		assertFalse(wl1.equals(null));
		assertFalse(wl1.equals(new Object()));
	}

	@Test(dataProvider = "dataForTestBulkWorkloadRequestEquality")
	public void testBulkWorkloadRequestEquality(BulkWorkloadRequest wl1, BulkWorkloadRequest wl2, boolean expected) {
		assertEquals(wl1.equals(wl2), expected);
	}

	@DataProvider
	private Object[][] dataForTestBulkWorkloadRequestEquality() {
		BulkWorkloadRequest wl1 = new BulkWorkloadRequest();
		List<DomainServices> requestList = new ArrayList<>();
		requestList.add(new DomainServices().setDomainName("athenz").setServiceNames(Arrays.asList("api")));
		wl1.setApplicableStaticTypes(Arrays.asList(StaticWorkloadType.VIP_LB));
		wl1.init();
		wl1.setDomainServices(requestList);

		BulkWorkloadRequest wl2 = new BulkWorkloadRequest();
		requestList = new ArrayList<>();
		requestList.add(new DomainServices().setDomainName("athenz").setServiceNames(Arrays.asList("api")));
		wl2.setApplicableStaticTypes(Arrays.asList(StaticWorkloadType.VIP_LB));
		wl2.setFetchDynamicTypeWorkloads(true);
		wl2.setResolveStaticWorkloads(false);
		wl2.setDomainServices(requestList);
		wl2.init();

		BulkWorkloadRequest wl3 = new BulkWorkloadRequest();
		requestList = new ArrayList<>();
		requestList.add(new DomainServices().setDomainName("athenz").setServiceNames(Arrays.asList("api")));
		wl3.setApplicableStaticTypes(Arrays.asList(StaticWorkloadType.VIP_LB));
		wl3.setFetchStaticTypeWorkloads(true);
		wl3.setResolveStaticWorkloads(true);
		wl3.setDomainServices(requestList);
		wl3.init();

		BulkWorkloadRequest wl4 = new BulkWorkloadRequest();
		requestList = new ArrayList<>();
		requestList.add(new DomainServices().setDomainName("athenz").setServiceNames(Arrays.asList("api")));
		wl4.setApplicableStaticTypes(Arrays.asList(StaticWorkloadType.VIP_LB));
		wl4.setFetchDynamicTypeWorkloads(true);
		wl4.setFetchStaticTypeWorkloads(false);
		wl4.setResolveStaticWorkloads(false);
		wl4.setDomainServices(requestList);

		BulkWorkloadRequest wl5 = new BulkWorkloadRequest();
		requestList = new ArrayList<>();
		requestList.add(new DomainServices().setDomainName("athenz").setServiceNames(Arrays.asList("api")));
		wl5.setApplicableStaticTypes(Arrays.asList(StaticWorkloadType.VIP_LB));
		wl5.setFetchDynamicTypeWorkloads(false);
		wl5.setFetchStaticTypeWorkloads(true);
		wl5.setResolveStaticWorkloads(false);
		wl5.setDomainServices(requestList);

		BulkWorkloadRequest wl6 = new BulkWorkloadRequest();
		requestList = new ArrayList<>();
		requestList.add(new DomainServices().setDomainName("athenz").setServiceNames(Arrays.asList("api")));
		wl6.setApplicableStaticTypes(Arrays.asList(StaticWorkloadType.VIP));
		wl6.setFetchDynamicTypeWorkloads(true);
		wl6.setFetchStaticTypeWorkloads(true);
		wl6.setResolveStaticWorkloads(false);
		wl6.setDomainServices(requestList);

		BulkWorkloadRequest wl7 = new BulkWorkloadRequest();
		requestList = new ArrayList<>();
		requestList.add(new DomainServices().setDomainName("athenz").setServiceNames(Arrays.asList("msd")));
		wl7.setApplicableStaticTypes(Arrays.asList(StaticWorkloadType.VIP_LB));
		wl7.setFetchDynamicTypeWorkloads(true);
		wl7.setFetchStaticTypeWorkloads(true);
		wl7.setResolveStaticWorkloads(false);
		wl7.setDomainServices(requestList);

		return new Object[][] {
			{ wl1, wl1, true },
			{ wl1, wl2, true },
			{ wl1, wl3, false },
			{ wl1, wl4, false },
			{ wl1, wl5, false },
			{ wl1, wl6, false },
			{ wl1, wl7, false },
			{ new BulkWorkloadRequest(), new BulkWorkloadRequest(), true },
			{ new BulkWorkloadRequest(), new BulkWorkloadRequest(), true },
		};
	}

	@Test(dataProvider = "dateForTestBulkWorkloadEquality")
	public void testBulkWorkloadEquality(DomainServices wl1, DomainServices wl2, boolean expected) {
		assertEquals(wl1.equals(wl2), expected);
	}

	@DataProvider
	private Object[][] dateForTestBulkWorkloadEquality() {
		DomainServices ds1 = new DomainServices();
		ds1.setDomainName("athenz");
		ds1.setServiceNames(Arrays.asList("api"));

		DomainServices ds2 = new DomainServices();
		ds2.setDomainName("athenz");
		ds2.setServiceNames(Arrays.asList("api"));

		DomainServices ds3 = new DomainServices();
		ds3.setDomainName("athenz");
		ds3.setServiceNames(Arrays.asList("msd"));

		DomainServices ds4 = new DomainServices();
		ds4.setDomainName("athenz-msd");
		ds4.setServiceNames(Arrays.asList("api"));

		return new Object[][] {
			{ ds1, ds2, true },
			{ ds1, ds3, false },
			{ ds1, ds4, false }
		};
	}

    @Test (dataProvider = "dataForTestBulkWorkloadRequestValidation")
    public void testBulkWorkloadRequestValidation(BulkWorkloadRequest wl1, boolean expected) {

        Schema schema = MSDSchema.instance();
        Validator validator = new Validator(schema);
        Validator.Result result = validator.validate(wl1, "BulkWorkloadRequest");
        assertEquals(result.valid, expected);
    }

    @DataProvider
    private Object[][] dataForTestBulkWorkloadRequestValidation() {
    	BulkWorkloadRequest wl1 = new BulkWorkloadRequest();
        List<DomainServices> requestList = new ArrayList<>();
        requestList.add(new DomainServices().setDomainName("athenz").setServiceNames(Arrays.asList("api")));
        wl1.setApplicableStaticTypes(Arrays.asList(StaticWorkloadType.VIP_LB));
        wl1.setFetchDynamicTypeWorkloads(true);
        wl1.setFetchStaticTypeWorkloads(false);
        wl1.setResolveStaticWorkloads(true);
        wl1.setDomainServices(requestList);

    	return new Object[][] {
                {wl1, true},
        };
    }
}