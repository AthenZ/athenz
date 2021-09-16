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

/**
 * Factory to create various static workload validators
 */
public interface StaticWorkloadValidatorFactory {

    /**
     * Creates the static workload validators
     */
    void create();

    /**
     * Get an appropriate static workload validator based on the type parameter
     * @param type static workload type {@link com.yahoo.athenz.msd.StaticWorkloadType}
     * @return static workload validator
     */
    default StaticWorkloadValidator getByType(String type) {
        return new NoOpValidator();
    }
}
