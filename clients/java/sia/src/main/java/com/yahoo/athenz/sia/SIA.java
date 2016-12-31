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
package com.yahoo.athenz.sia;

import java.io.IOException;
import java.util.ArrayList;

import com.yahoo.athenz.auth.Principal;

public interface SIA {

    /**
     * For the specified domain/service return the corresponding Service Principal that
     * includes the SIA generated PrincipalToken (NToken)
     * @param domainName name of the domain
     * @param serviceName name of the service
     * @param minExpiryTime (optional) specifies that the returned PrincipalToken must be
     *          at least valid (min/lower bound) for specified number of seconds,
     * @param maxExpiryTime (optional) specifies that the returned PrincipalToken must be
     *          at most valid (max/upper bound) for specified number of seconds.
     * @param ignoreCache ignore the cache and retrieve the token from SIA Server
     * @return SIA generated Principal object with PrincipalToken
     * @throws IOException for any IO errors
     */
    public Principal getServicePrincipal(String domainName, String serviceName,
            Integer minExpiryTime, Integer maxExpiryTime, boolean ignoreCache) throws IOException;
    
    /**
     * Returns the list of domains that have private keys registered on this host
     * @return List of domain names
     * @throws IOException for any IO errors
     */
    public ArrayList<String> getDomainList() throws IOException;
}
