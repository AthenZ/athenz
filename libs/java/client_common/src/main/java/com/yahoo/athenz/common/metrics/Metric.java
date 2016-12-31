/**
 * Copyright 2016 Yahoo Inc.
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
package com.yahoo.athenz.common.metrics;

public interface Metric {

    /**
     * Increment the counter for the specified metric
     * @param metric Name of the counter
     */
    public void increment(String metric);
    
    /**
     * Increment the counter for the specified metric for the given domainName
     * @param metric Name of the counter
     * @param domainName Name of the domain. domainName is optional can be
     * passed as null to indicate that the counter is global and not per-domain
     */
    public void increment(String metric, String domainName);
    
    /**
     * Increment the sum by the specified count for the given metric against the domainName
     * @param metric Name of the counter
     * @param domainName Name of the domain. domainName is optional can be
     * passed as null to indicate that the counter is global and not per-domain
     * @param count amount inwhich to increment the metric sum
     */
    public void increment(String metric, String domainName, int count);
    
    /**
     * Start the latency timer for the specified metric for the given domainName.
     * The implementation must be able to support simultaneous handling of
     * multiple timer counters (but not the same metric). It's possible that
     * the application/lib started a latency timer for a metric but will not call
     * the stopTiming method of the request didn't complete successfully since
     * we only want to keep track of average latency time for successfully
     * completed requests.
     * @param metric Name of the counter
     * @param domainName Name of the domain. domainName is optional can be
     * passed as null to indicate that the counter is global and not per-domain
     * @return timer object. The server will use this as the argument to 
     * the stopTiming method to indicate that the operation has completed
     * and the time must be recorded for the metric.
     */
    public Object startTiming(String metric, String domainName);
    
    /**
     * Stop the latency timer for the specified metric.
     * @param timerMetric timer object that was returned by the startTiming
     * method call.
     */
    public void stopTiming(Object timerMetric);
    
    /**
     * Flush any buffered metrics to destination.
     */
    public void flush();
    
    /**
     * Flush buffers and shutdown any tasks.
     */
    public void quit();
}

