/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.common.server.paramstore;

/**
 * An interface that allows dynamic parameters to be loaded into the application.
 */
public interface DynamicParameterStore {

    /**
     * Get parameter value
     * @param param - parameter name
     * @return - the parameter value
     */
    String get(String param);

    /**
     * Get parameter value, with default value if not presented
     * @param param - parameter name
     * @param defaultValue - default value
     * @return - the parameter value or its default
     */
    String get(String param, String defaultValue);
}
