/**
 * Copyright 2016 Yahoo Inc.
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
package com.yahoo.athenz.zpe;

import java.util.List;
import java.util.Map;

import com.yahoo.athenz.auth.token.RoleToken;
import com.yahoo.rdl.Struct;


public interface ZpeClient {
    
    // @param domain can be null
    public void init(String domain);

    // return current cache of role tokens
    public  Map<String, RoleToken> getRoleTokenCacheMap();

    // return the role assertion map for the specified domain with allow effect
    // key is role name, value is List of assertions for that role
    public Map<String, List<Struct>> getRoleAllowAssertions(String domain);

    // return the wildcard role assertion map for the specified domain with allow effect
    // key is role name, value is List of assertions for that role
    public Map<String, List<com.yahoo.rdl.Struct>> getWildcardAllowAssertions(String domain);

    // return the role assertion map for the specified domain with deny effect
    // key is role name, value is List of assertions for that role
    public Map<String, List<com.yahoo.rdl.Struct>> getRoleDenyAssertions(String domain);

    // return the wildcard role assertion map for the specified domain with deny effect
    // key is role name, value is List of assertions for that role
    public Map<String, List<com.yahoo.rdl.Struct>> getWildcardDenyAssertions(String domain);
}

