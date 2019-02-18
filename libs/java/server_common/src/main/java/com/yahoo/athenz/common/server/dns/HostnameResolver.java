/*
 * Copyright 2019 Oath Holdings Inc.
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
package com.yahoo.athenz.common.server.dns;

public interface HostnameResolver {

    /**
     * Verifies if the given hostname is valid or not. This could be
     * a standard dns resolution or if the setup has a separate
     * source of truth for dns data, the implementation will query
     * that source if the hostname is valid or not.
     * @param hostname Instance hostname to check for validity
     * @return true if the hostname is valid, false otherwise
     */
    default boolean isValidHostname(final String hostname) {
        return true;
    }
}
