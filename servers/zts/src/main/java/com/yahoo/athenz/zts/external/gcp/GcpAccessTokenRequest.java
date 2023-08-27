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

package com.yahoo.athenz.zts.external.gcp;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

public class GcpAccessTokenRequest {

    private List<String> scope;
    private String lifetime;

    public List<String> getScope() {
        return scope;
    }

    public void setScope(List<String> scope) {
        this.scope = scope;
    }

    public String getLifetime() {
        return lifetime;
    }

    public void setLifetime(String lifetime) {
        this.lifetime = lifetime;
    }

    public void setLifetimeSeconds(int lifetimeSeconds) {
        this.lifetime = lifetimeSeconds + "s";
    }

    public void setScopeList(String scopes) {
        this.scope = Arrays.asList(Stream.of(scopes.split(" ")).filter(scope -> !scope.isEmpty()).toArray(String[]::new));
    }
}
