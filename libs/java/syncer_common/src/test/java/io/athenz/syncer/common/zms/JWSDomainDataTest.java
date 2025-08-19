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

import com.yahoo.athenz.zms.JWSDomain;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

public class JWSDomainDataTest {

    @Test
    public void testConstructorAndGetters() {
        // Create a mock JWSDomain
        JWSDomain mockJwsDomain = Mockito.mock(JWSDomain.class);
        long testTime = System.currentTimeMillis();

        // Create JWSDomainData instance
        JWSDomainData jwsDomainData = new JWSDomainData(mockJwsDomain, testTime);

        // Verify the constructor properly initialized the fields
        assertNotNull(jwsDomainData);

        // Verify getter methods return expected values
        assertEquals(jwsDomainData.getJwsDomain(), mockJwsDomain);
        assertEquals(jwsDomainData.getFetchTime(), testTime);
    }
}