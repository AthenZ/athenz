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
 */

package com.yahoo.athenz.zts.token;

/**
 * Error factory used by {@link TokenIssuancePolicy} so that each caller keeps
 * control over how errors are logged, metered and represented.
 */
public interface TokenIssuanceErrors {

    /**
     * @param msg error message
     * @param caller api name
     * @param requestDomain request domain name
     * @param principalDomain principal domain name
     * @return bad request exception
     */
    RuntimeException requestError(String msg, String caller, String requestDomain, String principalDomain);

    /**
     * @param msg error message
     * @param caller api name
     * @param requestDomain request domain name
     * @param principalDomain principal domain name
     * @return forbidden exception
     */
    RuntimeException forbiddenError(String msg, String caller, String requestDomain, String principalDomain);
}
