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
package io.athenz.syncer.gcp;

import io.athenz.syncer.common.zms.CloudZmsSyncer;
import io.athenz.syncer.gcp.common.impl.GcsDomainStoreFactory;
import io.athenz.syncer.gcp.common.impl.GcsStateFileBuilderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.invoke.MethodHandles;

public class SyncHelper {
    private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    protected CloudZmsSyncer createCloudZmsSyncer() throws Exception {
        return new CloudZmsSyncer();
    }

    public boolean run() {
        try {
            setRequiredProperties();
            return CloudZmsSyncer.launchSyncer(createCloudZmsSyncer());
        } catch (Exception e) {
            LOG.error("zms domain syncer failure", e);
            return false;
        }
    }

    public void setRequiredProperties() {
        System.getProperties().putIfAbsent(CloudZmsSyncer.SYNC_PROP_CLOUD_DOMAIN_STORE_FACTORY_CLASS, GcsDomainStoreFactory.class.getName());
        System.getProperties().putIfAbsent(CloudZmsSyncer.SYNC_PROP_STATEFILE_BUILDER_FACTORY_CLASS, GcsStateFileBuilderFactory.class.getName());
    }
}
