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
package com.yahoo.athenz.common.server.assertion;

import com.yahoo.athenz.zms.ResourceAccessList;
import java.util.Map;

/**
 * An interface that allows system administrators to take extra additional
 * action to write the assertion resource value based on the specific action.
 * This interface is called for the ResourceAccessList API.
 */
public interface ResourceValueUpdater {

    /**
     * Update the resource value in the given access list based on the
     * provided cloud information. The filter parameter is provided to
     * allow the implementation to limit the update to a specific set
     * of resources.
     *
     * @param accessList ResourceAccessList object containing the assertions
     * @param cloudProviderMap map of cloud information if required
     * @param filter filter string to limit the update scope
     */
    void updateResourceValue(ResourceAccessList accessList, Map<String, String> cloudProviderMap, final String filter);

    /**
     * Return the cloud provider map key required for the implementation.
     * If the implementation does not require any cloud information then
     * it should return null or empty string. If required, when calling
     * the updateResourceValue method, the cloudMap parameter will
     * contain the key with the corresponding cloud provider value.
     * @return cloud provider map key required for the implementation
     * currently supported values are "aws", "gcp", or "azure".
     */
    String cloudProviderMapRequired();
}
