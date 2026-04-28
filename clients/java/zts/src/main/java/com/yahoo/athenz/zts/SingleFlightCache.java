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

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class SingleFlightCache<T> {

    private static final Logger LOG = LoggerFactory.getLogger(SingleFlightCache.class);

    interface Fetcher<T> {
        T fetch() throws Exception;
    }

    private final ConcurrentHashMap<String, CompletableFuture<T>> inFlight = new ConcurrentHashMap<>();
    private volatile long timeoutMs;

    SingleFlightCache(long timeoutMs) {
        this.timeoutMs = timeoutMs;
    }

    void setTimeoutMs(long timeoutMs) {
        this.timeoutMs = timeoutMs;
    }

    T execute(String key, Fetcher<T> fetcher) throws Exception {

        CompletableFuture<T> future = new CompletableFuture<>();
        CompletableFuture<T> existing = inFlight.putIfAbsent(key, future);

        if (existing != null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("SingleFlight: waiting for in-flight request key={}", key);
            }
            return waitForResult(existing);
        }

        try {
            T result = fetcher.fetch();
            future.complete(result);
            return result;
        } catch (Exception ex) {
            future.completeExceptionally(ex);
            throw ex;
        } finally {
            inFlight.remove(key, future);
        }
    }

    private T waitForResult(CompletableFuture<T> future) throws Exception {
        try {
            return future.get(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (ExecutionException ex) {
            Throwable cause = ex.getCause();
            if (cause instanceof Exception) {
                throw (Exception) cause;
            }
            throw new RuntimeException(cause);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw ex;
        } catch (TimeoutException ex) {
            throw new ZTSClientException(ClientResourceException.SERVICE_UNAVAILABLE,
                    "single flight timeout waiting for in-flight request");
        }
    }

    int inFlightSize() {
        return inFlight.size();
    }
}
