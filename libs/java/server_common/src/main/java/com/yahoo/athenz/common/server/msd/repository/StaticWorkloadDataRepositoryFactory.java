/*
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package com.yahoo.athenz.common.server.msd.repository;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.dns.HostnameResolver;
import com.yahoo.athenz.common.server.msd.MsdStore;
import com.yahoo.athenz.msd.StaticWorkloadType;

/**
 * Factory to create various static workload data repositories
 */
public interface StaticWorkloadDataRepositoryFactory {

    /**
     * Creates the Repository objects
     * @param privateKeyStore used to fetch necessary secrets to initialize the repository
     * @param hostnameResolver used to resolve hostnames to ip addresses
     * @param msdStore used to fetch workload data from underlying storage
     * @param type type of static workload to get appropriate repository from the factory implementation
     * @return static workload data repository object
     */
    <T> StaticWorkloadDataRepository<T> create(final PrivateKeyStore privateKeyStore, final HostnameResolver hostnameResolver, final MsdStore msdStore,
                                           final StaticWorkloadType type);
}
