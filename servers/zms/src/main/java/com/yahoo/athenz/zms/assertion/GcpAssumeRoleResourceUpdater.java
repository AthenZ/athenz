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
package com.yahoo.athenz.zms.assertion;

import com.yahoo.athenz.common.server.assertion.ResourceValueUpdater;
import com.yahoo.athenz.common.server.store.ObjectStoreConnection;
import com.yahoo.athenz.zms.Assertion;
import com.yahoo.athenz.zms.ResourceAccess;
import com.yahoo.athenz.zms.ResourceAccessList;
import com.yahoo.athenz.zms.utils.ZMSUtils;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class GcpAssumeRoleResourceUpdater implements ResourceValueUpdater {

    private static final Logger LOG = LoggerFactory.getLogger(GcpAssumeRoleResourceUpdater.class);

    private static final String GCP_ARN_PREFIX  = "projects/";

    @Override
    public void updateResourceValue(ResourceAccessList accessList, Map<String, String> cloudProviderMap, String filter) {

        // if the gcp domain list is empty then we'll be removing all resources

        if (cloudProviderMap == null || cloudProviderMap.isEmpty()) {
            accessList.setResources(Collections.emptyList());
            return;
        }

        // we're going to update each assertion and generate the
        // resource in the expected gcp role format. however, we
        // are going to remove any assertions where we do not have a
        // valid syntax or no gcp domain

        List<ResourceAccess> resourceAccessList = accessList.getResources();
        for (ResourceAccess resourceAccess : resourceAccessList) {
            Iterator<Assertion> assertionIterator = resourceAccess.getAssertions().iterator();
            while (assertionIterator.hasNext()) {

                Assertion assertion = assertionIterator.next();

                final String role = assertion.getRole();
                final String resource = assertion.getResource();

                if (LOG.isDebugEnabled()) {
                    LOG.debug("processing assertion: {}/{}", role, resource);
                }

                // verify that role and resource domains match

                final String resourceDomain = ZMSUtils.assertionDomainCheck(role, resource);
                if (resourceDomain == null) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("assertion domain check failed, removing assertion");
                    }
                    assertionIterator.remove();
                    continue;
                }

                final String gcpProject = cloudProviderMap.get(resourceDomain);
                if (gcpProject == null) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("resource without gcp project: {}", resourceDomain);
                    }
                    assertionIterator.remove();
                    continue;
                }

                if (!StringUtil.isEmpty(filter) && !gcpProject.equals(filter)) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("resource with gcp project: {} not matching filter: {}", gcpProject, filter);
                    }
                    assertionIterator.remove();
                    continue;
                }

                final String resourceObject = resource.substring(resourceDomain.length() + 1);
                final String resourceComp = (resourceObject.startsWith("roles/") || resourceObject.startsWith("groups/")
                        || resourceObject.startsWith("services/")) ? "/" : "/roles/";
                assertion.setResource(GCP_ARN_PREFIX + gcpProject + resourceComp + resourceObject);
            }
        }
    }

    @Override
    public String cloudProviderMapRequired() {
        return ObjectStoreConnection.PROVIDER_GCP;
    }
}
