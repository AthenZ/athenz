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
package com.yahoo.athenz.common.server.store.impl;

import com.yahoo.athenz.common.server.store.ChangeLogStore;
import com.yahoo.athenz.zms.JWSDomain;
import com.yahoo.athenz.zms.SignedDomain;
import com.yahoo.athenz.zms.SignedDomains;
import org.testng.annotations.Test;

import java.util.List;
import java.util.Set;

import static org.testng.Assert.assertNull;

public class ChangeLogStoreTest {

    @Test
    public void testChangeLogStore() {

        ChangeLogStore store = new ChangeLogStore() {
            @Override
            public SignedDomain getLocalSignedDomain(String domainName) {
                return null;
            }

            @Override
            public SignedDomain getServerSignedDomain(String domainName) {
                return null;
            }

            @Override
            public void removeLocalDomain(String domainName) {
            }

            @Override
            public void saveLocalDomain(String domainName, SignedDomain signedDomain) {
            }

            @Override
            public List<String> getLocalDomainList() {
                return null;
            }

            @Override
            public Set<String> getServerDomainList() {
                return null;
            }

            @Override
            public SignedDomains getServerDomainModifiedList() {
                return null;
            }

            @Override
            public SignedDomains getUpdatedSignedDomains(StringBuilder lastModTimeBuffer) {
                return null;
            }

            @Override
            public void setLastModificationTimestamp(String lastModTime) {
            }

            @Override
            public boolean supportsFullRefresh() {
                return false;
            }
        };

        assertNull(store.getLocalJWSDomain("domain"));
        assertNull(store.getServerJWSDomain("domain"));
        assertNull(store.getUpdatedJWSDomains(null));
        store.saveLocalDomain("domain", new JWSDomain());
        store.setRequestConditions(true);
        store.setRequestConditions(false);
        store.setJWSDomainSupport(true);
        store.setJWSDomainSupport(false);
    }
}
