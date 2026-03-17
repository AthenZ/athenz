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
import org.testng.annotations.Test;

import static com.yahoo.athenz.common.ServerCommonConsts.ZTS_PROP_AWS_BUCKET_NAME;
import static com.yahoo.athenz.common.ServerCommonConsts.ZTS_PROP_AWS_REGION_NAME;
import static org.testng.Assert.*;

public class S3FilteredChangeLogStoreFactoryTest {

    private static final String ZTS_PROP_S3_CHANGE_LOG_STORE_FILTER = "athenz.zts.s3_change_log_store_filter";

    @Test
    public void testCreateStoreNullFilter() {
        System.clearProperty(ZTS_PROP_S3_CHANGE_LOG_STORE_FILTER);
        S3FilteredChangeLogStoreFactory factory = new S3FilteredChangeLogStoreFactory();
        try {
            factory.create(null, null, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertTrue(ex.getMessage().contains("athenz.zts.s3_change_log_store_filter"));
        }
    }

    @Test
    public void testCreateStoreValidFilter() {
        System.setProperty(ZTS_PROP_AWS_BUCKET_NAME, "s3-unit-test-bucket-name");
        System.setProperty(ZTS_PROP_AWS_REGION_NAME, "us-west-1");
        System.setProperty(ZTS_PROP_S3_CHANGE_LOG_STORE_FILTER, "iaas");

        S3FilteredChangeLogStoreFactory factory = new S3FilteredChangeLogStoreFactory();
        ChangeLogStore store = factory.create(null, null, null);
        assertNotNull(store);
        assertTrue(store instanceof S3FilteredChangeLogStore);

        System.clearProperty(ZTS_PROP_S3_CHANGE_LOG_STORE_FILTER);
    }

    @Test
    public void testCreateStoreMultipleDomains() {
        System.setProperty(ZTS_PROP_AWS_BUCKET_NAME, "s3-unit-test-bucket-name");
        System.setProperty(ZTS_PROP_AWS_REGION_NAME, "us-west-1");
        System.setProperty(ZTS_PROP_S3_CHANGE_LOG_STORE_FILTER, "iaas,cd.docker,platforms");

        S3FilteredChangeLogStoreFactory factory = new S3FilteredChangeLogStoreFactory();
        ChangeLogStore store = factory.create(null, null, null);
        assertNotNull(store);
        assertTrue(store instanceof S3FilteredChangeLogStore);

        System.clearProperty(ZTS_PROP_S3_CHANGE_LOG_STORE_FILTER);
    }

    @Test
    public void testCreateStoreWithWhitespace() {
        System.setProperty(ZTS_PROP_AWS_BUCKET_NAME, "s3-unit-test-bucket-name");
        System.setProperty(ZTS_PROP_AWS_REGION_NAME, "us-west-1");
        System.setProperty(ZTS_PROP_S3_CHANGE_LOG_STORE_FILTER, " iaas , cd.docker , platforms ");

        S3FilteredChangeLogStoreFactory factory = new S3FilteredChangeLogStoreFactory();
        ChangeLogStore store = factory.create(null, null, null);
        assertNotNull(store);
        assertTrue(store instanceof S3FilteredChangeLogStore);

        System.clearProperty(ZTS_PROP_S3_CHANGE_LOG_STORE_FILTER);
    }
}
