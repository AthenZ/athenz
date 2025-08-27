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
import com.yahoo.athenz.zms.ZMSConsts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;

public class ResourceUpdaterManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(ResourceUpdaterManager.class);

    public static final String ZMS_PROP_ASSERTION_RESOURCE_UPDATERS = "athenz.zms.assertion_resource_updaters";

    String awsAssumeRoleAction = null;
    String gcpAssumeRoleAction = null;
    String gcpAssumeServiceAction = null;
    HashMap<String, ResourceValueUpdater> assertionResourceValueUpdaters;

    public ResourceUpdaterManager() {

        assertionResourceValueUpdaters = new HashMap<>();

        final String resourceUpdaters = System.getProperty(ZMS_PROP_ASSERTION_RESOURCE_UPDATERS, "");

        // if there are no custom resource updaters defined then we'll fall back
        // to our default set of resource updaters to maintain backward compatibility

        if (resourceUpdaters.isEmpty()) {

            awsAssumeRoleAction = System.getProperty(ZMSConsts.ZMS_PROP_AWS_ASSUME_ROLE_ACTION,
                    ZMSConsts.ACTION_ASSUME_AWS_ROLE);
            gcpAssumeRoleAction = System.getProperty(ZMSConsts.ZMS_PROP_GCP_ASSUME_ROLE_ACTION,
                    ZMSConsts.ACTION_ASSUME_GCP_ROLE);
            gcpAssumeServiceAction = System.getProperty(ZMSConsts.ZMS_PROP_GCP_ASSUME_SERVICE_ACTION,
                    ZMSConsts.ACTION_ASSUME_GCP_SERVICE);

            assertionResourceValueUpdaters.put(awsAssumeRoleAction, new AwsAssumeRoleResourceUpdater());
            assertionResourceValueUpdaters.put(gcpAssumeRoleAction, new GcpAssumeRoleResourceUpdater());
            assertionResourceValueUpdaters.put(gcpAssumeServiceAction, new GcpAssumeRoleResourceUpdater());

        } else {

            // the format of the attribute is action:class,action:class,...
            // so we'll parse it and load each of the classes

            String[] resourceUpdaterList = resourceUpdaters.split(",");
            for (String resourceUpdater : resourceUpdaterList) {
                String[] actionAndClass = resourceUpdater.trim().split(":");
                if (actionAndClass.length != 2) {
                    throw new IllegalArgumentException("Invalid assertion resource updater: " + resourceUpdater);
                }
                assertionResourceValueUpdaters.put(actionAndClass[0].trim(),
                        getResourceValueUpdater(actionAndClass[1].trim()));
            }
        }
    }

    ResourceValueUpdater getResourceValueUpdater(final String className) {

        LOGGER.debug("Loading resource value updater {}...", className);

        ResourceValueUpdater updater;
        try {
            updater = (ResourceValueUpdater) Class.forName(className).getDeclaredConstructor().newInstance();
        } catch (Exception ex) {
            throw new IllegalArgumentException("Invalid resource updater class: " + className, ex);
        }
        return updater;
    }

    public ResourceValueUpdater getResourceValueUpdaterForAction(final String action) {
        return assertionResourceValueUpdaters.get(action);
    }
}
