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
import com.yahoo.athenz.msd.StaticWorkloadType;

/**
 * Factory to create various static workload validators
 */
public interface StaticWorkloadValidatorFactory {

    /**
     * Creates the static workload validators
     * @param type static workload type {@link com.yahoo.athenz.msd.StaticWorkloadType}
     * @param repository repository associated with the corresponding static workload type to be instantiated
     * @return static workload validator
     */
    default StaticWorkloadValidator create(final StaticWorkloadType type, final StaticWorkloadDataRepository<?> repository) {
        return new NoOpStaticWorkloadValidator();
    }
}
