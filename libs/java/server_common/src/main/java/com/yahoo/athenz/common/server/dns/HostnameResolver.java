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
package com.yahoo.athenz.common.server.dns;

import com.yahoo.athenz.zts.CertType;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

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

    /**
     * returns the set of IP addresses that host resolves to
     * @param host name of the host
     * @return a set of IP addresses as strings
     */
    default Set<String> getAllByName(String host) {
        return new HashSet<>();
    }

    /**
     * Verifies if the given CNAMEs are valid for a given hostname. This could be
     * a standard dns resolution or if the setup has a separate
     * source of truth for dns data, the implementation will query
     * that source if the hostname CNAME is valid or not.
     * @param serviceFqn fully qualified service name of the request Principal
     * @param hostname Instance hostname to check for CNAME validity
     * @param cnameList list of host CNAMEs to check for validity
     * @param certType one of X509, SSHHOST, SSHUSER
     * @return true if the hostname CNAME is valid, false otherwise
     */
    default boolean isValidHostCnameList(final String serviceFqn, final String hostname, final List<String> cnameList, CertType certType) {
        return false;
    }
}
