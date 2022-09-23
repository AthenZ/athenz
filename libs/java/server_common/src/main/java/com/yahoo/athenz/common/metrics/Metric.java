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
package com.yahoo.athenz.common.metrics;

public interface Metric {

    /**
     * Increment the counter for the specified metric
     * @param metric Name of the counter
     */
    void increment(String metric);

    /**
     * Increment the counter for the specified metric for the given domainName
     * @param metric Name of the counter
     * @param requestDomainName Name of the request domain. requestDomainName is
     *      optional and can be passed as null to indicate that the counter is
     *      global and not per-domain
     */
    void increment(String metric, String requestDomainName);

    /**
     * Increment the counter for the specified metric for the given domainName
     * by a service from a given principal domain
     * @param metric Name of the counter
     * @param requestDomainName Name of the request domain. requestDomainName is
     *      optional and can be passed as null to indicate that the counter is
     *      global and not per-domain
     * @param principalDomainName Name of the principal domain. principalDomainName is
     *      optional and can be passed as null in case the request has no principal
     */
    default void increment(String metric, String requestDomainName, String principalDomainName) {
        increment(metric, requestDomainName);
    }

    /**
     * Increment the sum by the specified count for the given metric against the domainName
     * @param metric Name of the counter
     * @param requestDomainName Name of the request domain. requestDomainName is
     *      optional and can be passed as null to indicate that the counter is
     *      global and not per-domain
     * @param count amount in which to increment the metric sum
     */
    void increment(String metric, String requestDomainName, int count);

    /**
     * Increment the sum by the specified count for the given metric against the domainName
     * @param metric Name of the counter
     * @param requestDomainName Name of the request domain. requestDomainName is
     *      optional and can be passed as null to indicate that the counter is
     *      global and not per-domain
     * @param principalDomainName Name of the principal domain. principalDomainName is
     *      optional and can be passed as null in case the request has no principal
     * @param count amount in which to increment the metric sum
     */
    default void increment(String metric, String requestDomainName, String principalDomainName, int count) {
        increment(metric, requestDomainName, count);
    }

    /**
     * Increment the counter by the specified count for the given request metric
     * @param metric Name of the counter
     * @param requestDomainName Name of the request domain. requestDomainName is
     *      optional and can be passed as null to indicate that the counter is
     *      global and not per-domain
     * @param principalDomainName Name of the principal domain. principalDomainName is
     *      optional and can be passed as null in case the request has no principal
     * @param httpMethod - HTTP Method type (GET / POST / PUT / DELETE)
     * @param httpStatus - Request HTTP Status (200 - OK, 404 - Not Found etc)
     * @param apiName - Name of the API method
     */
    default void increment(String metric, String requestDomainName, String principalDomainName, String httpMethod, int httpStatus, String apiName) {
        increment(metric, requestDomainName);
    }

    /**
     * Increment the counter for the specified metric with the specified attributes
     * @param metric Name of the counter
     * @param attributes a sorted array of tag key-value pairs in a flattened array
     */
    default void increment(String metric, final String... attributes) {
        // No op
    }

    /**
     * Increment the counter for the specified metric with the specified attributes
     * @param metric Name of the counter
     * @param attributes a sorted array of tag key-value pairs in a flattened array
     * @param change value by which to increment the counter
     */
    default void increment(String metric, long change, final String... attributes) {
        // No op
    }

    /**
     * Start the latency timer for the specified metric for the given domainName.
     * The implementation must be able to support simultaneous handling of
     * multiple timer counters (but not the same metric). It's possible that
     * the application/lib started a latency timer for a metric but will not call
     * the stopTiming method of the request didn't complete successfully since
     * we only want to keep track of average latency time for successfully
     * completed requests.
     * @param metric Name of the counter
     * @param requestDomainName Name of the request domain. requestDomainName is
     *      optional and can be passed as null to indicate that the counter is
     *      global and not per-domain
     * @return timer object. The server will use this as the argument to
     *      the stopTiming method to indicate that the operation has completed
     *      and the time must be recorded for the metric.
     */
    Object startTiming(String metric, String requestDomainName);

    /**
     * Start the latency timer for the specified metric for the given domainName.
     * The implementation must be able to support simultaneous handling of
     * multiple timer counters (but not the same metric). It's possible that
     * the application/lib started a latency timer for a metric but will not call
     * the stopTiming method of the request didn't complete successfully since
     * we only want to keep track of average latency time for successfully
     * completed requests.
     * @param metric Name of the counter
     * @param requestDomainName Name of the request domain. requestDomainName is
     *      optional and can be passed as null to indicate that the counter is
     *      global and not per-domain
     * @param principalDomainName Name of the principal domain. principalDomainName is
     *      optional and can be passed as null in case the request has no principal
     * @return timer object. The server will use this as the argument to
     *      the stopTiming method to indicate that the operation has completed
     *      and the time must be recorded for the metric.
     */
    default Object startTiming(String metric, String requestDomainName, String principalDomainName) {
        return startTiming(metric, requestDomainName);
    }

    /**
     * Start the latency timer for the specified metric for the given domainName.
     * The implementation must be able to support simultaneous handling of
     * multiple timer counters (but not the same metric). It's possible that
     * the application/lib started a latency timer for a metric but will not call
     * the stopTiming method of the request didn't complete successfully since
     * we only want to keep track of average latency time for successfully
     * completed requests.
     * @param metric Name of the counter
     * @param requestDomainName Name of the request domain. requestDomainName is
     *      optional and can be passed as null to indicate that the counter is
     *      global and not per-domain
     * @param principalDomainName Name of the principal domain. principalDomainName is
     *      optional and can be passed as null in case the request has no principal
     * @param httpMethod - HTTP Method type (GET / POST / PUT / DELETE)
     * @param apiName - Name of the API method
     * @return timer object. The server will use this as the argument to
     *      the stopTiming method to indicate that the operation has completed
     *      and the time must be recorded for the metric.
     */
    default Object startTiming(String metric, String requestDomainName, String principalDomainName, String httpMethod, String apiName) {
        return startTiming(metric, requestDomainName);
    }

    /**
     * Stop the latency timer for the specified metric.
     * @param timerMetric timer object that was returned by the startTiming
     * method call.
     */
    void stopTiming(Object timerMetric);

    /**
     * Stop the latency timer for the specified metric.
     * @param timerMetric timer object that was returned by the startTiming
     * @param requestDomainName Name of the request domain. requestDomainName is
     *      optional and can be passed as null to indicate that the counter is
     *      global and not per-domain
     * @param principalDomainName Name of the principal domain. principalDomainName is
     *      optional and can be passed as null in case the request has no principal
     */
    default void stopTiming(Object timerMetric, String requestDomainName, String principalDomainName) {
        stopTiming(timerMetric);
    }

    /**
     * Stop the latency timer for the specified metric.
     * @param timerMetric timer object that was returned by the startTiming
     * @param requestDomainName Name of the request domain. requestDomainName is
     *      optional and can be passed as null to indicate that the counter is
     *      global and not per-domain
     * @param principalDomainName Name of the principal domain. principalDomainName is
     *      optional and can be passed as null in case the request has no principal
     * @param httpMethod - HTTP Method type (GET / POST / PUT / DELETE)
     * @param httpStatus - Request HTTP Status (200 - OK, 404 - Not Found etc)
     * @param apiName - Name of the API method
     */
    default void stopTiming(Object timerMetric, String requestDomainName, String principalDomainName, String httpMethod, int httpStatus, String apiName) {
        stopTiming(timerMetric);
    }

    /**
     * Flush any buffered metrics to destination.
     */
    void flush();

    /**
     * Flush buffers and shutdown any tasks.
     */
    void quit();
}

