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

import java.util.Collection;

/*
 * Service Providers will implement this interface for special env needs
 * whereby retrieving a role token from zts server may not be feasible.
 * The provider implementation will need to be specified in the clients package
 * in the file: META-INF/services/com.yahoo.athenz.zts.ZTSClientService
 **/
public interface ZTSClientService {

    /**
     *  Athenz token client cache entry
     */
    class RoleTokenDescriptor {

        /**
         * Construct the object with any needed params. Note there are no setters.
         * @param signedToken signed role token from zts - required
         */
        public RoleTokenDescriptor(String signedToken) {
            this.signedToken = signedToken;
        }

        public String getSignedToken() {
            return signedToken;
        }

        final String signedToken;
    }

    /**
     * ZTSClient calls to pre-load the Athenz client token cache.
     * @return collection of RoleTokenDescriptor objects that include
     *      the service retrieved role tokens. It can return either an
     *      empty set or null if there are no tokens to pre-load.
     */
    default Collection<RoleTokenDescriptor> loadTokens() {
        return null;
    }

    /**
     * ZTSClient will use this implementation to get a role token and avoid using the
     * cache if a token is returned. If no token is returned, ZTSClient will process
     * in the usual way - lookup in the cache (if not disabled) and then if not
     * found contact ZTS Server directly to retrieve the role token.
     *
     * For the specified requester(user/service) return the corresponding Role Token that
     * includes the list of roles that the principal has access to in the specified domain
     * @param clientDomainName client's domain name that is requesting this role token
     * @param clientServiceName client's service name that is requesting this role token
     * @param domainName name of the domain to retrieve a role from
     * @param roleName (optional) only interested in roles with this value
     * @param minExpiryTime (optional) specifies that the returned RoleToken must be
     *          at least valid (min/lower bound) for specified number of seconds,
     * @param maxExpiryTime (optional) specifies that the returned RoleToken must be
     *          at most valid (max/upper bound) for specified number of seconds.
     * @param proxyForPrincipal (optional) this request is proxy for this principal
     * @return ZTS generated Role Token. Must return null if not available/found.
     */
    default RoleToken fetchToken(String clientDomainName, String clientServiceName,
                                 String domainName, String roleName, Integer minExpiryTime, Integer maxExpiryTime,
                                 String proxyForPrincipal) {
        return null;
    }
}

