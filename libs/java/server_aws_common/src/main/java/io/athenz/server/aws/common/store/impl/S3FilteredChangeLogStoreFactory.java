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

package io.athenz.server.aws.common.store.impl;

import com.yahoo.athenz.common.server.store.ChangeLogStore;
import com.yahoo.athenz.common.server.store.ChangeLogStoreFactory;

import java.security.PrivateKey;
import java.util.HashSet;
import java.util.Set;

/*
 * Factory class for creating a filtered change log store implementation
 * that only lists objects which match the supported domains. This is useful
 * when the ZTS is only deployed to issue user certificates and not to store
 * any data in the datastore. This is useful to reduce the load on the ZTS and
 * the datastore. With the user certificate support, the datastore is only used
 * to store the details about the provider service in the configured domain so
 * there is no need to monitor and load data for all domains. This, of course,
 * depends on the deployment configuration and the use case. With this factory,
 * the ZTS instance can be deployed to only issue user certificates and not to
 * issue any oauth2 access tokens nor service x.509 identity certificates.
 */
public class S3FilteredChangeLogStoreFactory implements ChangeLogStoreFactory {

    private static final String ZTS_PROP_S3_CHANGE_LOG_STORE_FILTER = "athenz.zts.s3_change_log_store_filter";

    @Override
    public ChangeLogStore create(String ztsHomeDir, PrivateKey privateKey, String privateKeyId) {

        // to use the filtered change log store, we must have the configuration property
        // that includes the list of domains to filter

        String filter = System.getProperty(ZTS_PROP_S3_CHANGE_LOG_STORE_FILTER);
        if (filter == null) {
            throw new IllegalArgumentException("athenz.zts.s3_change_log_store_filter property is required for the change log store");
        }

        // generate a list of domains to filter. the value is a comma separated list
        // of domains to filter.

        Set<String> domains = new HashSet<>();
        for (String domain : filter.split(",")) {
            domains.add(domain.trim());
        }

        if (domains.isEmpty()) {
            throw new IllegalArgumentException("athenz.zts.s3_change_log_store_filter property must include at least one domain to filter");
        }

        return new S3FilteredChangeLogStore(domains);
    }
}
