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

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.testng.annotations.Test;

public class SingleFlightCacheTest {

    @Test
    public void testSingleFetch() throws Exception {
        SingleFlightCache<String> cache = new SingleFlightCache<>(5000);
        AtomicInteger fetchCount = new AtomicInteger(0);

        String result = cache.execute("key1", () -> {
            fetchCount.incrementAndGet();
            return "value1";
        });

        assertEquals(result, "value1");
        assertEquals(fetchCount.get(), 1);
        assertEquals(cache.inFlightSize(), 0);
    }

    @Test
    public void testConcurrentFetchSameKey() throws Exception {
        SingleFlightCache<String> cache = new SingleFlightCache<>(5000);
        AtomicInteger fetchCount = new AtomicInteger(0);
        int threadCount = 10;

        CyclicBarrier barrier = new CyclicBarrier(threadCount);
        CountDownLatch latch = new CountDownLatch(threadCount);
        AtomicReference<String> firstResult = new AtomicReference<>();
        AtomicInteger successCount = new AtomicInteger(0);

        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        for (int i = 0; i < threadCount; i++) {
            executor.submit(() -> {
                try {
                    barrier.await(5, TimeUnit.SECONDS);
                    String result = cache.execute("same-key", () -> {
                        fetchCount.incrementAndGet();
                        Thread.sleep(100);
                        return "shared-value";
                    });
                    firstResult.compareAndSet(null, result);
                    assertEquals(result, "shared-value");
                    successCount.incrementAndGet();
                } catch (Exception e) {
                    // timeout or interruption - acceptable in test
                } finally {
                    latch.countDown();
                }
            });
        }

        latch.await(10, TimeUnit.SECONDS);
        executor.shutdown();

        assertEquals(fetchCount.get(), 1, "Only one fetch should have been executed");
        assertEquals(successCount.get(), threadCount, "All threads should have received the result");
        assertEquals(cache.inFlightSize(), 0);
    }

    @Test
    public void testConcurrentFetchDifferentKeys() throws Exception {
        SingleFlightCache<String> cache = new SingleFlightCache<>(5000);
        AtomicInteger fetchCount = new AtomicInteger(0);

        CyclicBarrier barrier = new CyclicBarrier(3);
        CountDownLatch latch = new CountDownLatch(3);

        ExecutorService executor = Executors.newFixedThreadPool(3);
        for (int i = 0; i < 3; i++) {
            final String key = "key-" + i;
            executor.submit(() -> {
                try {
                    barrier.await(5, TimeUnit.SECONDS);
                    cache.execute(key, () -> {
                        fetchCount.incrementAndGet();
                        Thread.sleep(50);
                        return "value-" + key;
                    });
                } catch (Exception e) {
                    // ignore
                } finally {
                    latch.countDown();
                }
            });
        }

        latch.await(10, TimeUnit.SECONDS);
        executor.shutdown();

        assertEquals(fetchCount.get(), 3, "Each key should trigger its own fetch");
        assertEquals(cache.inFlightSize(), 0);
    }

    @Test
    public void testFetcherException() throws Exception {
        SingleFlightCache<String> cache = new SingleFlightCache<>(5000);
        AtomicInteger fetchCount = new AtomicInteger(0);
        int threadCount = 5;

        CyclicBarrier barrier = new CyclicBarrier(threadCount);
        CountDownLatch latch = new CountDownLatch(threadCount);
        AtomicInteger exceptionCount = new AtomicInteger(0);

        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        for (int i = 0; i < threadCount; i++) {
            executor.submit(() -> {
                try {
                    barrier.await(5, TimeUnit.SECONDS);
                    cache.execute("error-key", () -> {
                        fetchCount.incrementAndGet();
                        Thread.sleep(50);
                        throw new ClientResourceException(ClientResourceException.NOT_FOUND, "not found");
                    });
                    fail("Should have thrown exception");
                } catch (ClientResourceException e) {
                    assertEquals(e.getCode(), ClientResourceException.NOT_FOUND);
                    exceptionCount.incrementAndGet();
                } catch (Exception e) {
                    // barrier/other exceptions
                } finally {
                    latch.countDown();
                }
            });
        }

        latch.await(10, TimeUnit.SECONDS);
        executor.shutdown();

        assertEquals(fetchCount.get(), 1, "Only one fetch should have been executed");
        assertEquals(exceptionCount.get(), threadCount, "All threads should have received the exception");
        assertEquals(cache.inFlightSize(), 0);
    }

    @Test
    public void testTimeout() throws Exception {
        SingleFlightCache<String> cache = new SingleFlightCache<>(100);
        CountDownLatch fetchStarted = new CountDownLatch(1);
        CountDownLatch latch = new CountDownLatch(1);

        // start a slow fetch in another thread
        Thread fetcher = new Thread(() -> {
            try {
                cache.execute("slow-key", () -> {
                    fetchStarted.countDown();
                    Thread.sleep(5000);
                    return "slow-value";
                });
            } catch (Exception e) {
                // expected interruption
            }
        });
        fetcher.start();

        fetchStarted.await(5, TimeUnit.SECONDS);

        // this thread should timeout waiting for the slow fetch
        try {
            cache.execute("slow-key", () -> "fast-value");
            fail("Should have thrown timeout exception");
        } catch (ZTSClientException e) {
            assertEquals(e.getCode(), ClientResourceException.SERVICE_UNAVAILABLE);
            assertTrue(e.getMessage().contains("single flight timeout"));
        }

        fetcher.interrupt();
        fetcher.join(5000);
    }

    @Test
    public void testCleanupAfterCompletion() throws Exception {
        SingleFlightCache<String> cache = new SingleFlightCache<>(5000);

        cache.execute("cleanup-key", () -> "value");
        assertEquals(cache.inFlightSize(), 0, "In-flight map should be empty after completion");
    }

    @Test
    public void testCleanupAfterException() throws Exception {
        SingleFlightCache<String> cache = new SingleFlightCache<>(5000);

        try {
            cache.execute("error-cleanup-key", () -> {
                throw new RuntimeException("test error");
            });
            fail("Should have thrown exception");
        } catch (RuntimeException e) {
            assertEquals(e.getMessage(), "test error");
        }

        assertEquals(cache.inFlightSize(), 0, "In-flight map should be empty after exception");
    }

    @Test
    public void testSequentialFetchesSameKey() throws Exception {
        SingleFlightCache<String> cache = new SingleFlightCache<>(5000);
        AtomicInteger fetchCount = new AtomicInteger(0);

        String result1 = cache.execute("seq-key", () -> {
            fetchCount.incrementAndGet();
            return "value1";
        });

        String result2 = cache.execute("seq-key", () -> {
            fetchCount.incrementAndGet();
            return "value2";
        });

        assertEquals(result1, "value1");
        assertEquals(result2, "value2");
        assertEquals(fetchCount.get(), 2, "Sequential fetches should each execute independently");
    }
}
