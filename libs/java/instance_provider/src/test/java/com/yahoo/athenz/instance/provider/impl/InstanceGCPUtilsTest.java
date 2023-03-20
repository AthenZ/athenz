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

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.util.ArrayMap;
import com.yahoo.athenz.auth.token.IdToken;
import com.yahoo.athenz.auth.util.Crypto;
import io.jsonwebtoken.SignatureAlgorithm;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.io.*;

import java.math.BigDecimal;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.Map;

import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.testng.Assert.*;

public class InstanceGCPUtilsTest {

    private final File ecPrivateKey = new File("./src/test/resources/unit_test_ec_private.key");

    @Test
    public void testInitialize() {
        System.setProperty(InstanceGCPUtils.GCP_PROP_EXPECTED_AUDIENCE, "https://zts.athenz.io");
        InstanceGCPUtils utils = new InstanceGCPUtils();
        assertNotNull(utils.googleIdTokenVerifier);
        System.clearProperty(InstanceGCPUtils.GCP_PROP_EXPECTED_AUDIENCE);
    }

    @Test
    public void testInitializeNoAudience() {
        InstanceGCPUtils utils = new InstanceGCPUtils();
        assertNotNull(utils.googleIdTokenVerifier);
    }

    @Test
    public void testValidateGCPSignatureInvalid() {
        System.setProperty(InstanceGCPUtils.GCP_PROP_EXPECTED_AUDIENCE, "https://zts.athenz.io");
        InstanceGCPUtils utils = new InstanceGCPUtils();

        // invalid jwt
        assertNull(utils.validateGCPIdentityToken("invalidjwt", new StringBuilder()));

        // valid jwt but invalid id token
        IdToken sampleToken = new IdToken();
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String nonGoogleToken = sampleToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
        assertNull(utils.validateGCPIdentityToken(nonGoogleToken, new StringBuilder()));

        System.clearProperty(InstanceGCPUtils.GCP_PROP_EXPECTED_AUDIENCE);
    }

    @Test
    public void testValidateGCPSignature() throws GeneralSecurityException, IOException {
        System.setProperty(InstanceGCPUtils.GCP_PROP_EXPECTED_AUDIENCE, "https://zts.athenz.io");

        IdToken sampleToken = new IdToken();
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String nonGoogleToken = sampleToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);


        GoogleIdTokenVerifier googleIdTokenVerifierMock = Mockito.mock(GoogleIdTokenVerifier.class);
        GoogleIdToken idTokenMock = Mockito.mock(GoogleIdToken.class);
        Mockito.when(googleIdTokenVerifierMock.verify(any(GoogleIdToken.class))).thenReturn(true);
        Mockito.when(googleIdTokenVerifierMock.verify(anyString())).thenReturn(idTokenMock);


        InstanceGCPUtils utils = new InstanceGCPUtils();
        utils.setGoogleIdTokenVerifier(googleIdTokenVerifierMock);
        try {
            utils.validateGCPIdentityToken(nonGoogleToken, new StringBuilder());
        } catch (Exception ex) {
            fail();
        }

        System.clearProperty(InstanceGCPUtils.GCP_PROP_EXPECTED_AUDIENCE);
    }

    @Test
    public void testPopulateAttestationData() {
        GoogleIdToken.Payload payload = new GoogleIdToken.Payload();
        payload.setAudience("https://my-zts-server");
        payload.setIssuer("https://accounts.google.com");
        payload.setEmail("my-sa@my-gcp-project.iam.gserviceaccount.com");
        payload.setEmailVerified(true);
        payload.setAuthorizedParty("102023896904281105569");

        Map<String, Map<String, Object>> extras = new ArrayMap<>();
        Map<String, Object> extrasCE = new ArrayMap<>();
        extrasCE.put("instance_creation_timestamp", new BigDecimal(1677459985444L));
        extrasCE.put("instance_id", "3692465099344887023");
        extrasCE.put("instance_name", "my-vm");
        extrasCE.put("project_id", "my-gcp-project");
        extrasCE.put("project_number", new BigDecimal(1234567890123L));
        extrasCE.put("zone", "us-west1-a");
        extras.put("compute_engine", extrasCE);

        payload.set("google", extras);

        GCPDerivedAttestationData derivedAttestationData = new GCPDerivedAttestationData();

        InstanceGCPUtils utils = new InstanceGCPUtils();
        utils.populateAttestationData(payload, derivedAttestationData);

        assertThat(derivedAttestationData.getAudience(), hasItems("https://my-zts-server"));
        assertEquals(derivedAttestationData.getEmail(), "my-sa@my-gcp-project.iam.gserviceaccount.com");
        assertTrue(derivedAttestationData.isEmailVerified());
        assertEquals(derivedAttestationData.getIssuer(), "https://accounts.google.com");
        assertEquals(derivedAttestationData.getAuthorizedParty(), "102023896904281105569");

        assertNotNull(derivedAttestationData.getAdditionalAttestationData());

        assertEquals(derivedAttestationData.getAdditionalAttestationData().getInstanceId(), "3692465099344887023");
        assertEquals(derivedAttestationData.getAdditionalAttestationData().getInstanceCreationTimestamp().longValue(), 1677459985444L);
        assertEquals(derivedAttestationData.getAdditionalAttestationData().getInstanceName(), "my-vm");
        assertEquals(derivedAttestationData.getAdditionalAttestationData().getProjectId(), "my-gcp-project");
        assertEquals(derivedAttestationData.getAdditionalAttestationData().getProjectNumber(), "1234567890123");
        assertEquals(derivedAttestationData.getAdditionalAttestationData().getZone(), "us-west1-a");
    }

    @Test
    public void testGetServiceNameFromAttestedData() {

        InstanceGCPUtils utils = new InstanceGCPUtils();
        GCPDerivedAttestationData derivedAttestationData = new GCPDerivedAttestationData();
        derivedAttestationData.setEmailVerified(true);
        derivedAttestationData.setEmail("my-sa@my-gcp-project.iam.gserviceaccount.com");
        assertEquals(utils.getServiceNameFromAttestedData(derivedAttestationData), "my-gcp-project.my-sa");
    }

    @Test
    public void testGetServiceNameFromAttestedDataInvalid() {

        InstanceGCPUtils utils = new InstanceGCPUtils();
        GCPDerivedAttestationData derivedAttestationData = new GCPDerivedAttestationData();
        derivedAttestationData.setEmail("xyz");
        assertEquals(utils.getServiceNameFromAttestedData(derivedAttestationData), ".");
    }

    @Test
    public void testGetServiceNameFromAttestedDataUnverified() {

        InstanceGCPUtils utils = new InstanceGCPUtils();
        GCPDerivedAttestationData derivedAttestationData = new GCPDerivedAttestationData();
        derivedAttestationData.setEmailVerified(false);
        derivedAttestationData.setEmail("acc@a.com");
        assertEquals(utils.getServiceNameFromAttestedData(derivedAttestationData), ".");
    }

    @Test
    public void testGetProjectIdFromAttestedData() {

        InstanceGCPUtils utils = new InstanceGCPUtils();
        GCPDerivedAttestationData derivedAttestationData = new GCPDerivedAttestationData();
        derivedAttestationData.setEmailVerified(true);
        derivedAttestationData.setEmail("my-sa@my-gcp-project.iam.gserviceaccount.com");
        assertEquals(utils.getProjectIdFromAttestedData(derivedAttestationData), "my-gcp-project");
    }

    @Test
    public void testGetProjectIdFromAttestedDataInvalid() {

        InstanceGCPUtils utils = new InstanceGCPUtils();
        GCPDerivedAttestationData derivedAttestationData = new GCPDerivedAttestationData();
        derivedAttestationData.setEmail("xyz");
        assertEquals(utils.getProjectIdFromAttestedData(derivedAttestationData), "");
    }

    @Test
    public void testGetProjectIdFromAttestedDataUnverified() {

        InstanceGCPUtils utils = new InstanceGCPUtils();
        GCPDerivedAttestationData derivedAttestationData = new GCPDerivedAttestationData();
        derivedAttestationData.setEmailVerified(false);
        derivedAttestationData.setEmail("acc@a.com");
        assertEquals(utils.getProjectIdFromAttestedData(derivedAttestationData), "");
    }

    @Test
    public void testGetGCPRegionFromZone() {
        InstanceGCPUtils utils = new InstanceGCPUtils();
        String actual = utils.getGCPRegionFromZone("us-west1-a");
        assertEquals(actual, "us-west1");
    }

    @Test
    public void testGetGCPRegionFromZoneNull() {
        InstanceGCPUtils utils = new InstanceGCPUtils();
        String actual = utils.getGCPRegionFromZone(null);
        assertNull(actual);
    }

    @Test
    public void testGetGCPRegionFromZoneInvalid() {
        InstanceGCPUtils utils = new InstanceGCPUtils();
        String actual = utils.getGCPRegionFromZone("uswest1");
        assertEquals(actual, "uswest1");
    }
}