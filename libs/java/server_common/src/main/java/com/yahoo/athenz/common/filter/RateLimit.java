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

package com.yahoo.athenz.common.filter;

import com.yahoo.athenz.common.metrics.Metric;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;

public interface RateLimit {

    /**
     * filter based on rate limit
     * @param servletRequest  ServletRequest
     * @param servletResponse ServletResponse
     * @return boolean too many request
     */
    @Deprecated
    boolean filter(ServletRequest servletRequest, ServletResponse servletResponse);

    /**
     * filter based on rate limit
     * @param servletRequest  ServletRequest
     * @param servletResponse ServletResponse
     * @param metric Metric object to report any observability data
     * @return boolean too many request
     */
    default boolean filter(ServletRequest servletRequest, ServletResponse servletResponse, Metric metric) {
        return filter(servletRequest, servletResponse);
    }
}
