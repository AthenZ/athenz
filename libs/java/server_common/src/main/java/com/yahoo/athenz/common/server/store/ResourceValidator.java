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

package com.yahoo.athenz.common.server.store;

/**
 * External validator for resources managed by Athenz
 */
public interface ResourceValidator {

    /**
     * Validate the member for the given role and/or group
     * @param domainName domain name
     * @param roleName role name
     * @param memberName member name
     * @return true if the member is valid, false otherwise
     */
    boolean validateRoleMember(String domainName, String roleName, String memberName);

    /**
     * Validate the member for the given group
     * @param domainName domain name
     * @param groupName group name
     * @param memberName member name
     * @return true if the member is valid, false otherwise
     */
    boolean validateGroupMember(String domainName, String groupName, String memberName);
}
