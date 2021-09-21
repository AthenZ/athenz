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

package com.yahoo.athenz.common.server.msd.validator;

import com.yahoo.athenz.common.server.msd.repository.StaticWorkloadDataRepository;

/**
 * Static workload validator interface
 */
public interface StaticWorkloadValidator {

    /**
     * Initializes the validator
     * @param repository static workload data repository used by the validator for source of truth data
     */
    <T> void initialize(StaticWorkloadDataRepository<T> repository);

    /**
     * Validates the static workload entry against the business rules and / or repository
     * @param domain input domain of the static workload entry
     * @param service input service of the static workload entry
     * @param name static workload entry ( usually a Domain name like abc.example.com, but can be an IP address )
     * @return validation status
     */
    boolean validateWorkload(String domain, String service, String name);
}
