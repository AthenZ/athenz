/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.common.server.paramstore;

import com.yahoo.athenz.common.server.rest.ResourceException;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.model.*;

import java.util.Date;

import static com.yahoo.athenz.common.server.rest.ResourceException.INTERNAL_SERVER_ERROR;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class MockAWSParameterStoreSyncer extends AWSParameterStoreSyncer {

	@Override
	SsmClient initClient() {
		Date now = new Date();
		SsmClient mock = mock(SsmClient.class);
		when(mock.describeParameters(any(DescribeParametersRequest.class)))
			.thenReturn(DescribeParametersResponse.builder()
				.parameters(
					ParameterMetadata.builder().name("param1").lastModifiedDate(now.toInstant()).build(),
					ParameterMetadata.builder().name("param2").lastModifiedDate(now.toInstant()).build(),
					ParameterMetadata.builder().name("param4").lastModifiedDate(now.toInstant()).build()
				).build()
			);

		when(mock.getParameter(parameterRequest("param1")))
			.thenReturn(GetParameterResponse.builder()
				.parameter(
					Parameter.builder().name("param1").value("param1-val").lastModifiedDate(now.toInstant()).build()
				).build()
			);
		when(mock.getParameter(parameterRequest("param2")))
			.thenReturn(GetParameterResponse.builder()
				.parameter(
					Parameter.builder().name("param2").value("param2-val").lastModifiedDate(now.toInstant()).build()
				).build()
			);
		when(mock.getParameter(parameterRequest("param4")))
			.thenThrow(new ResourceException(INTERNAL_SERVER_ERROR));
		return mock;
	}

	private GetParameterRequest parameterRequest(String paramName) {
		return GetParameterRequest.builder()
			.name(paramName)
			.withDecryption(true)
			.build();
	}

	public void setClientResult(String param, String value) {
		when(ssmClient.getParameter(any(GetParameterRequest.class)))
			.thenReturn(GetParameterResponse.builder()
				.parameter(
					Parameter.builder().name(param).value(value).lastModifiedDate(new Date().toInstant()).build()
				).build()
			);
	}

}
