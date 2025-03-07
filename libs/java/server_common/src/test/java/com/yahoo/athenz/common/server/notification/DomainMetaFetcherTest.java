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

package com.yahoo.athenz.common.server.notification;

import com.yahoo.athenz.common.server.db.DomainProvider;
import com.yahoo.athenz.zms.Domain;
import org.testng.annotations.Test;

import java.util.*;

import static com.yahoo.athenz.common.ServerCommonConsts.USER_DOMAIN_PREFIX;
import static org.junit.Assert.assertNull;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

public class DomainMetaFetcherTest {

    @Test
    public void testGetDomainMeta() {
        Domain domain1 = new Domain();
        domain1.setName("domain1");
        domain1.setSlackChannel("channel-1");

        DomainProvider provider = new DomainProvider() {
            @Override
            public Domain getDomain(String domainName, boolean masterCopy) {
                return domain1;
            }
        };

        DomainMetaFetcher fetcher = new DomainMetaFetcher(provider);
        NotificationDomainMeta domainMeta = fetcher.getDomainMeta("domain1", false);
        assertEquals(domainMeta.getDomainName(), "domain1");
        assertEquals(domainMeta.getSlackChannel(), "channel-1");
    }

    @Test
    public void testGetDomainMetaNull() {
        DomainProvider provider = new DomainProvider() {
            @Override
            public Domain getDomain(String domainName, boolean masterCopy) {
                return null;
            }
        };

        DomainMetaFetcher fetcher = new DomainMetaFetcher(provider);
        NotificationDomainMeta domainMeta = fetcher.getDomainMeta("domain1", false);
        assertNull(domainMeta);

        // null provider
        fetcher = new DomainMetaFetcher(null);
        domainMeta = fetcher.getDomainMeta("domain1", false);
        assertNull(domainMeta);
    }

    @Test
    public void testGetDomainMetaException() {
        DomainProvider provider = new DomainProvider() {
            @Override
            public Domain getDomain(String domainName, boolean masterCopy) {
                throw new IllegalArgumentException("invalid domain");
            }
        };

        DomainMetaFetcher fetcher = new DomainMetaFetcher(provider);
        NotificationDomainMeta domainMeta = fetcher.getDomainMeta("domain1", false);
        assertNull(domainMeta);
    }
}
