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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class BulkWorkloadResponseTest {
	@Test
	public void testBulkWorkloadResponseFields() {
		BulkWorkloadResponse rs1 = new BulkWorkloadResponse();
		List<DomainServices> list = new ArrayList<>();
		list.add(new DomainServices().setDomainName("athenz").setServiceNames(Arrays.asList("api")));
		rs1.setUnmodifiedServices(list);
		rs1.setWorkloads(new Workloads());

		assertNotNull(rs1);
		assertNotNull(rs1.getUnmodifiedServices());
		assertNotNull(rs1.getWorkloads());
		assertFalse(rs1.equals(new Object()));
	}

	@Test(dataProvider = "dataForTestBulkWorkloadResponseEquality")
	public void testBulkWorkloadResponseEquality(BulkWorkloadResponse rs1, BulkWorkloadResponse rs2, boolean expected) {
		assertEquals(rs1.equals(rs2), expected);
	}

	@DataProvider
	private Object[][] dataForTestBulkWorkloadResponseEquality() {
		BulkWorkloadResponse rs1 = new BulkWorkloadResponse();
		rs1.setUnmodifiedServices(Arrays.asList(new DomainServices().setDomainName("athenz").setServiceNames(Arrays.asList("api"))));
		rs1.setWorkloads(new Workloads());

		BulkWorkloadResponse rs2 = new BulkWorkloadResponse();
		rs2.setUnmodifiedServices(Arrays.asList(new DomainServices().setDomainName("athenz").setServiceNames(Arrays.asList("api"))));

		BulkWorkloadResponse rs3 = new BulkWorkloadResponse();
		rs3.setUnmodifiedServices(Arrays.asList(new DomainServices().setDomainName("athenz").setServiceNames(Arrays.asList("msd"))));
		rs1.setWorkloads(new Workloads());

		BulkWorkloadResponse rs4 = new BulkWorkloadResponse();
		rs4.setUnmodifiedServices(Arrays.asList(new DomainServices().setDomainName("athenz").setServiceNames(Arrays.asList("api"))));
		rs4.setWorkloads(new Workloads());

		return new Object[][] {
			{ rs1, rs2, false },
			{ rs1, rs3, false },
			{ rs1, rs4, true }
		};
	}
}