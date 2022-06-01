/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.zms.store;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.zms.AuthHistory;
import com.yahoo.athenz.zms.AuthHistoryDependencies;
import com.yahoo.rdl.Timestamp;
import org.mockito.Mockito;

import java.util.ArrayList;
import java.util.List;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

public class MockAuthHistoryStoreFactory implements AuthHistoryStoreFactory {
    @Override
    public AuthHistoryStore create(PrivateKeyStore pkeyStore) {
        AuthHistoryStoreConnection authHistoryStoreConnection = Mockito.mock(AuthHistoryStoreConnection.class);

        // Domain with no auth history records
        AuthHistoryDependencies empty = new AuthHistoryDependencies();
        empty.setIncomingDependencies(new ArrayList<>());
        empty.setOutgoingDependencies(new ArrayList<>());
        when(authHistoryStoreConnection.getAuthHistory(eq("empty.domain"))).thenReturn(empty);

        // Domain with auth history records
        List<AuthHistory> incoming = new ArrayList<>();
        List<AuthHistory> outgoing = new ArrayList<>();
        int numberOfRecords = 500;
        for (int i = 0; i < numberOfRecords ; ++i) {
            incoming.add(generateRecordForTest(i));
        }
        for (int i = 500; i < numberOfRecords*2 ; ++i) {
            outgoing.add(generateRecordForTest(i));
        }
        AuthHistoryDependencies authHistoryDependencies = new AuthHistoryDependencies();
        authHistoryDependencies.setIncomingDependencies(incoming);
        authHistoryDependencies.setOutgoingDependencies(outgoing);
        when(authHistoryStoreConnection.getAuthHistory(eq("test.domain"))).thenReturn(authHistoryDependencies);

        // Domain with auth history records - one of the records has invalid timestamp
        List<AuthHistory> invalidTimestampRecords = new ArrayList<>();
        AuthHistory goodTimestamp = generateRecordForTest(0);
        AuthHistory badTimestamp = generateRecordForTest(1);
        badTimestamp.setTimestamp(null);
        invalidTimestampRecords.add(goodTimestamp);
        invalidTimestampRecords.add(badTimestamp);
        AuthHistoryDependencies authHistoryDependenciesInvalid = new AuthHistoryDependencies();
        authHistoryDependenciesInvalid.setIncomingDependencies(invalidTimestampRecords);
        authHistoryDependenciesInvalid.setOutgoingDependencies(new ArrayList<>());
        when(authHistoryStoreConnection.getAuthHistory(eq("invalid.timestamp.domain"))).thenReturn(authHistoryDependenciesInvalid);

        AuthHistoryStore authHistoryStore = Mockito.mock(AuthHistoryStore.class);
        when(authHistoryStore.getConnection()).thenReturn(authHistoryStoreConnection);
        return authHistoryStore;
    }

    public static AuthHistory generateRecordForTest(int index) {
        AuthHistory authHistory = new AuthHistory();
        authHistory.setUriDomain("test.domain" + index);
        authHistory.setPrincipalDomain("principal.domain" + index);
        authHistory.setPrincipalName("principal" + index);
        authHistory.setEndpoint("https://endpoint" + index + ".com");
        authHistory.setTimestamp(Timestamp.fromMillis(1655282257L + index));
        authHistory.setTtl(1655282257L + index);
        return authHistory;
    }
}
