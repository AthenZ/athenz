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

package com.yahoo.athenz.instance.provider.impl;

import org.testng.annotations.Test;

import java.util.List;

import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.testng.Assert.*;

public class GCPDerivedAttestationDataTest {

    @Test
    public void testFields() {
        GCPDerivedAttestationData derivedAttestationData = new GCPDerivedAttestationData();
        derivedAttestationData.setEmail("sa@gcp-project.iam.gserviceaccount.com");
        derivedAttestationData.setIssuer("https://google.com");
        derivedAttestationData.setAuthorizedParty("azp");
        derivedAttestationData.setAudience(List.of("https://my-aud"));
        derivedAttestationData.setEmailVerified(true);
        derivedAttestationData.setAdditionalAttestationData(new GCPAdditionalAttestationData());

        assertEquals(derivedAttestationData.getEmail(), "sa@gcp-project.iam.gserviceaccount.com");
        assertEquals(derivedAttestationData.getIssuer(), "https://google.com");
        assertEquals(derivedAttestationData.getAuthorizedParty(), "azp");
        assertThat(derivedAttestationData.getAudience(), hasItems("https://my-aud"));
        assertTrue(derivedAttestationData.isEmailVerified());
        assertNotNull(derivedAttestationData.getAdditionalAttestationData());

    }
}