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

import com.amazonaws.services.simplesystemsmanagement.AWSSimpleSystemsManagement;
import com.amazonaws.services.simplesystemsmanagement.model.*;
import com.yahoo.athenz.common.server.rest.ResourceException;

import java.util.Date;

import static com.yahoo.athenz.common.server.rest.ResourceException.INTERNAL_SERVER_ERROR;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class MockAWSParameterStoreSyncer extends AWSParameterStoreSyncer {

	@Override
	AWSSimpleSystemsManagement initClient() {
		Date now = new Date();
		AWSSimpleSystemsManagement mock = mock(AWSSimpleSystemsManagement.class);
		when(mock.describeParameters(any()))
				.thenReturn(new DescribeParametersResult()
						.withParameters(
								new ParameterMetadata().withName("param1").withLastModifiedDate(now),
								new ParameterMetadata().withName("param2").withLastModifiedDate(now),
								new ParameterMetadata().withName("param4").withLastModifiedDate(now)
						)
				);
		
		when(mock.getParameter(parameterRequest("param1")))
				.thenReturn(new GetParameterResult()
						.withParameter(
								new Parameter().withName("param1").withValue("param1-val").withLastModifiedDate(now)
						)
				);
		when(mock.getParameter(parameterRequest("param2")))
				.thenReturn(new GetParameterResult()
						.withParameter(
								new Parameter().withName("param2").withValue("param2-val").withLastModifiedDate(now)
						)
				);
		when(mock.getParameter(parameterRequest("param4")))
				.thenThrow(new ResourceException(INTERNAL_SERVER_ERROR));
		return mock;
	}

	private GetParameterRequest parameterRequest(String paramName) {
		return new GetParameterRequest()
				.withName(paramName)
				.withWithDecryption(true);
	}

	public void setClientResult(String param, String value) {
		when(ssmClient.getParameter(any()))
				.thenReturn(new GetParameterResult()
						.withParameter(
								new Parameter().withName(param).withValue(value).withLastModifiedDate(new Date())
						)
				);
	}
	
}
