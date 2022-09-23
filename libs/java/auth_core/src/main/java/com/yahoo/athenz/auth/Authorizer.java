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
 * An Authorizer is an entity that can authorize an assertion of access. An assertion consists of
 * an action performed on a resource by a principal. The resource includes its own domain information
 *, but an extra crossDomain argument can be specified to check another domain's idea of access on the
 * resource (to handle a cross-domain trust scenario). Normally the crossDomain argument should be null
 */
public interface Authorizer {
    /**
     * Check access, return true if access is granted, false otherwise.
     * @param resource - (ResourceName) the resource to check access against. Must include the domain.
     * @param action - (CompoundName) the action to check access for
     * @param principal - (ResourceName) the principal who will access the resource.
     * @param crossDomain - (DomainName) an alternate domain responsible for the policy involved. This is usually null.
     * @return true if access is granted for the action/resource/principal
     */
    boolean access(String action, String resource, Principal principal, String crossDomain);
}
