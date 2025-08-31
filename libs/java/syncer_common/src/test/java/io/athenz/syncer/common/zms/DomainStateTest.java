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
package io.athenz.syncer.common.zms;

import com.yahoo.athenz.zms.DomainData;
import com.yahoo.rdl.Timestamp;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import static org.mockito.Mockito.when;
import static org.testng.Assert.*;

public class DomainStateTest {

    private static final String TEST_DOMAIN = "test-domain";
    private static final String TEST_MODIFIED = "2023-05-15T10:30:00.000Z";
    private static final long TEST_FETCH_TIME = 1684140600000L;

    @Test
    public void testGetterAndSetters() {
        // Create a new DomainState instance
        DomainState domainState = new DomainState();

        // Test initial values are null/default
        assertNull(domainState.getDomain());
        assertNull(domainState.getModified());
        assertEquals(domainState.getFetchTime(), 0L);

        // Set values
        domainState.setDomain(TEST_DOMAIN);
        domainState.setModified(TEST_MODIFIED);
        domainState.setFetchTime(TEST_FETCH_TIME);

        // Verify getters return the correct values
        assertEquals(domainState.getDomain(), TEST_DOMAIN);
        assertEquals(domainState.getModified(), TEST_MODIFIED);
        assertEquals(domainState.getFetchTime(), TEST_FETCH_TIME);
    }

    @Test
    public void testGetDomainState() {
        // Mock DomainData
        DomainData mockDomainData = Mockito.mock(DomainData.class);
        when(mockDomainData.getName()).thenReturn(TEST_DOMAIN);
        when(mockDomainData.getModified()).thenReturn(Timestamp.fromObject(TEST_MODIFIED));

        // Call the factory method
        DomainState domainState = DomainState.getDomainState(mockDomainData, TEST_FETCH_TIME);

        // Verify the created object has the correct values
        assertNotNull(domainState);
        assertEquals(domainState.getDomain(), TEST_DOMAIN);
        assertEquals(domainState.getModified(), TEST_MODIFIED);
        assertEquals(domainState.getFetchTime(), TEST_FETCH_TIME);
    }

    @Test
    public void testDomainStateIndependence() {
        // This test verifies that changes to the original DomainData
        // don't affect the created DomainState object

        // Create a mutable mock that we can change after creating DomainState
        DomainData mockDomainData = Mockito.mock(DomainData.class);
        when(mockDomainData.getName()).thenReturn(TEST_DOMAIN);
        when(mockDomainData.getModified()).thenReturn(Timestamp.fromObject(TEST_MODIFIED));

        // Create DomainState
        DomainState domainState = DomainState.getDomainState(mockDomainData, TEST_FETCH_TIME);

        // Change the mock's return values
        when(mockDomainData.getName()).thenReturn("changed-domain");
        when(mockDomainData.getModified()).thenReturn(Timestamp.fromMillis(System.currentTimeMillis()));

        // Verify DomainState still has the original values
        assertEquals(domainState.getDomain(), TEST_DOMAIN);
        assertEquals(domainState.getModified(), TEST_MODIFIED);
    }
}