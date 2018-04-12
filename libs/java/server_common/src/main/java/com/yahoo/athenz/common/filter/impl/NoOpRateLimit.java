/*
 * Copyright 2017 Yahoo Holdings Inc.
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
package com.yahoo.athenz.common.filter.impl;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.common.filter.RateLimit;

public class NoOpRateLimit implements RateLimit {
    private static final Logger LOG = LoggerFactory.getLogger(NoOpRateLimit.class);

    @Override
    public boolean filter(ServletRequest servletRequest, ServletResponse servletResponse) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("NoOpRateLimit called");
        }
        return false;
    }

}
