/*
 * Copyright 2020 Verizon Media
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

package com.yahoo.athenz.common.server.notification;

import java.util.Set;

public interface DomainRoleMembersFetcher {
    /**
     * Common interface to fetch domain role members. ZMS, for example will fetch from it's DB while ZTS will fetch from cache.
     * @param domainName
     * @param roleName
     * @return List of domain role member names
     */
    Set<String> getDomainRoleMembers(String domainName, String roleName);
}
