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

package io.athenz.server.aws.common.paramstore.impl;

import com.yahoo.athenz.common.server.paramstore.DynamicParameterStore;
import com.yahoo.athenz.common.server.paramstore.DynamicParameterStoreFactory;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import software.amazon.awssdk.services.ssm.model.ParameterMetadata;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static com.yahoo.athenz.common.server.paramstore.DynamicParameterStoreFactory.DYNAMIC_PARAM_STORE_CLASS;
import static io.athenz.server.aws.common.paramstore.impl.SSMDynamicParameterStore.PROP_RELOAD_PARAMS_PERIOD;
import static io.athenz.server.aws.common.paramstore.impl.SSMDynamicParameterStore.PROP_PARAMETER_STORE_PARAM_PREFIX_LIST;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;

public class SSMDynamicParameterStoreTest {

	@BeforeClass
	public void setUp() {
		System.setProperty(DYNAMIC_PARAM_STORE_CLASS, "io.athenz.server.aws.common.paramstore.impl.MockSSMDynamicParameterStore");
		System.setProperty(PROP_RELOAD_PARAMS_PERIOD, "10000");
		DynamicParameterStoreFactory.create();
	}

	@Test
	public void testInitialize() {
		DynamicParameterStore dynamicParameterStore = DynamicParameterStoreFactory.getInstance();
		assertEquals(dynamicParameterStore.get("param1"), "param1-val");
		assertNull(dynamicParameterStore.get("param3"));
		assertEquals(dynamicParameterStore.get("param3", "def3"), "def3");
		assertNull(dynamicParameterStore.get("param4"));
	}

	@Test
	public void testSetParam() {
		MockSSMDynamicParameterStore mockAwsParameterStoreSyncer = (MockSSMDynamicParameterStore) DynamicParameterStoreFactory.getInstance();
		mockAwsParameterStoreSyncer.setClientResult("param2", "new-param2-val");
		mockAwsParameterStoreSyncer.storeParameters(
			Collections.singletonList(ParameterMetadata.builder()
				.name("param2")
				.lastModifiedDate(new Date().toInstant())
				.build())
		);
		assertEquals(mockAwsParameterStoreSyncer.get("param2"), "new-param2-val");
	}

	@Test
	public void testSetOlderParam() {
		MockSSMDynamicParameterStore mockAwsParameterStoreSyncer = (MockSSMDynamicParameterStore) DynamicParameterStoreFactory.getInstance();
		mockAwsParameterStoreSyncer.setClientResult("param1", "new-param1-val");

		// put param with older timestamp
		Instant now = Instant.now();
		mockAwsParameterStoreSyncer.storeParameters(
			Collections.singletonList(ParameterMetadata.builder().name("param1")
				.lastModifiedDate(now.minusSeconds( 24 * 60 * 60 ))
				.build())
		);

		assertEquals(mockAwsParameterStoreSyncer.get("param1"), "param1-val");
	}

	@Test
	public void testNullClient() {
		System.setProperty(PROP_PARAMETER_STORE_PARAM_PREFIX_LIST, "param");
		System.setProperty(DYNAMIC_PARAM_STORE_CLASS, "io.athenz.server.aws.common.paramstore.impl.AWSParameterStoreSyncer");
		DynamicParameterStore dynamicParameterStore = DynamicParameterStoreFactory.getInstance();
		assertNull(dynamicParameterStore.get("someParam"));
		assertEquals(dynamicParameterStore.get("someParam", "def"), "def");
		System.setProperty(DYNAMIC_PARAM_STORE_CLASS, "io.athenz.server.aws.common.paramstore.impl.MockAWSParameterStoreSyncer");
	}

	/*
	 * 20 threads total.
	 * writer task is to store parameter
	 * reader task is to verify the parameter exist in the map
	 */
	@Test
	public void testThreadSafeMap() {
		final int mapSize = 1000;
		MockSSMDynamicParameterStore mockAwsParameterStoreSyncer = (MockSSMDynamicParameterStore) DynamicParameterStoreFactory.getInstance();
		
		ExecutorService executorService = Executors.newFixedThreadPool(20);

		IntStream.range(0, mapSize)
			.boxed()
			.map(i -> Arrays.asList(writerTask(mockAwsParameterStoreSyncer, i), readerTask(mockAwsParameterStoreSyncer, i)))
			.flatMap(List::stream)
			.map(runnable -> CompletableFuture.runAsync(runnable, executorService))
			.collect(Collectors.toList())
			.forEach(CompletableFuture::join);

		executorService.shutdown();
	}

	/**
	 * Wite parameter to map
	 */
	private Runnable writerTask(MockSSMDynamicParameterStore awsParameterStoreSyncer, int counter) {
		return () -> awsParameterStoreSyncer.writeParameter("counter_" + counter, Integer.toString(counter), new Date().toInstant());
	}

	/**
	 * For readers, allow retry once only
	 */
	private Runnable readerTask(MockSSMDynamicParameterStore awsParameterStoreSyncer, int counter) {
		return () -> {
			String expectedCounter = "counter_" + counter;
			SSMDynamicParameterStore.ParameterHolder result = awsParameterStoreSyncer.readParameter(expectedCounter);
			if (result == null) {
				try {
					Thread.sleep(100);
				} catch (InterruptedException ignored) { }
				result = awsParameterStoreSyncer.readParameter(expectedCounter);
			}
			Assert.assertEquals(result.value, Integer.toString(counter));
		};
	}
}
