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

import org.joda.time.DateTime;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import software.amazon.awssdk.services.ssm.model.ParameterMetadata;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static com.yahoo.athenz.common.server.paramstore.AWSParameterStoreSyncer.PROP_PARAMETER_STORE_PARAM_PREFIX_LIST;
import static com.yahoo.athenz.common.server.paramstore.AWSParameterStoreSyncer.PROP_RELOAD_PARAMS_PERIOD;
import static com.yahoo.athenz.common.server.paramstore.DynamicParameterStoreFactory.DYNAMIC_PARAM_STORE_CLASS;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;

public class AWSParameterStoreSyncerTest {

	@BeforeClass
	public void setUp() {
		System.setProperty(DYNAMIC_PARAM_STORE_CLASS, "com.yahoo.athenz.common.server.paramstore.MockAWSParameterStoreSyncer");
		System.setProperty(PROP_RELOAD_PARAMS_PERIOD, "10000");
		initDynamicParameterStoreInstance();
		DynamicParameterStoreFactory.create();
	}

	@Test
	public void test_initialization() {
		DynamicParameterStore dynamicParameterStore = DynamicParameterStoreFactory.getInstance();
		assertEquals(dynamicParameterStore.get("param1"), "param1-val");
		assertNull(dynamicParameterStore.get("param3"));
		assertEquals(dynamicParameterStore.get("param3", "def3"), "def3");
		assertNull(dynamicParameterStore.get("param4"));
	}

	@Test
	public void set_param() {
		MockAWSParameterStoreSyncer mockAwsParameterStoreSyncer = (MockAWSParameterStoreSyncer) DynamicParameterStoreFactory.getInstance();
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
	public void set_older_param() {
		MockAWSParameterStoreSyncer mockAwsParameterStoreSyncer = (MockAWSParameterStoreSyncer) DynamicParameterStoreFactory.getInstance();
		mockAwsParameterStoreSyncer.setClientResult("param1", "new-param1-val");

		// put param with older timestamp
		DateTime now = DateTime.now();
		mockAwsParameterStoreSyncer.storeParameters(
			Collections.singletonList(ParameterMetadata.builder().name("param1")
				.lastModifiedDate(now.minusDays( 1 ).withTimeAtStartOfDay().toDate().toInstant())
				.build())
		);

		assertEquals(mockAwsParameterStoreSyncer.get("param1"), "param1-val");
	}

	@Test
	public void test_null_client() {
		System.setProperty(PROP_PARAMETER_STORE_PARAM_PREFIX_LIST, "param");
		System.setProperty(DYNAMIC_PARAM_STORE_CLASS, "com.yahoo.athenz.common.server.paramstore.AWSParameterStoreSyncer");
		initDynamicParameterStoreInstance();
		DynamicParameterStore dynamicParameterStore = DynamicParameterStoreFactory.getInstance();
		assertNull(dynamicParameterStore.get("someParam"));
		assertEquals(dynamicParameterStore.get("someParam", "def"), "def");
		System.setProperty(DYNAMIC_PARAM_STORE_CLASS, "com.yahoo.athenz.common.server.paramstore.MockAWSParameterStoreSyncer");
		initDynamicParameterStoreInstance();
	}

	/*
	 * 20 threads total.
	 * writer task is to store parameter
	 * reader task is to verify the parameter exist in the map
	 */
	@Test
	public void test_thread_safe_map() {
		final int mapSize = 1000;
		MockAWSParameterStoreSyncer mockAwsParameterStoreSyncer = (MockAWSParameterStoreSyncer) DynamicParameterStoreFactory.getInstance();
		
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
	private Runnable writerTask(MockAWSParameterStoreSyncer awsParameterStoreSyncer, int counter) {
		return () -> awsParameterStoreSyncer.writeParameter("counter_" + counter, Integer.toString(counter), new Date().toInstant());
	}

	/**
	 * For readers, allow retry once only
	 */
	private Runnable readerTask(MockAWSParameterStoreSyncer awsParameterStoreSyncer, int counter) {
		return () -> {
			String expectedCounter = "counter_" + counter;
			AWSParameterStoreSyncer.ParameterHolder result = awsParameterStoreSyncer.readParameter(expectedCounter);
			if (result == null) {
				try {
					Thread.sleep(100);
				} catch (InterruptedException ignored) { }
				result = awsParameterStoreSyncer.readParameter(expectedCounter);
			}
			Assert.assertEquals(result.value, Integer.toString(counter));
		};
	}

	public static void initDynamicParameterStoreInstance() {
		final Field parameterStoreInstance;
		try {
			DynamicParameterStore instance = DynamicParameterStoreFactory.getInstance();
			if (instance != null) {
				parameterStoreInstance = DynamicParameterStoreFactory.IDynamicParameterHolder.class.getDeclaredField("instance");
				parameterStoreInstance.setAccessible(true);
				parameterStoreInstance.set(instance, null);
			}
		} catch (final NoSuchFieldException | IllegalAccessException ignored) {
			throw new AssertionError("Failed to set DynamicParameterStoreFactory::instance");
		}
	}
}
