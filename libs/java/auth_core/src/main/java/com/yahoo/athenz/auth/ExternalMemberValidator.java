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
package com.yahoo.athenz.auth;

/**
 * An ExternalMemberValidator can validate whether a given member
 * is valid or not in an external system. This method is called
 * quite frequently so it should be efficient. The server will
 * instantiate a single instance of the validator for each domain
 * and use that instance for all operations in that domain. The
 * server will pass the domain name to the validator so that it can
 * make decisions based on the domain, if needed.
 */
public interface ExternalMemberValidator {

    /**
     * Validate if the given member is valid or not.
     * @param domainName the domain name where the member is being added
     * @param memberName the member name to validate
     * @return true if the member is valid, false otherwise
     */
    boolean validateMember(final String domainName, final String memberName);
}
