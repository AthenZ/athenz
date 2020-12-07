/*
 *  Copyright 2020 Verizon Media
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

package com.yahoo.athenz.common.server.db;

import com.yahoo.athenz.zms.Role;

import java.util.List;

/**
 * A common interface used by ZMS and ZTS for providing roles by domain
 */
public interface RolesProvider {
    /**
     *
     * @param domain
     * @return List of roles from the domain
     */
    List<Role> getRolesByDomain(String domain);
}
