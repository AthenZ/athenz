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
import com.google.api.client.util.ArrayMap;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.ResourceException;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.math.BigDecimal;
import java.util.HashMap;
import java.util.Map;

import static com.yahoo.athenz.instance.provider.InstanceProvider.*;
import static org.mockito.ArgumentMatchers.*;
import static org.testng.Assert.*;

public class InstanceGCPProviderTest {

    @BeforeMethod
    public void setup() {
        System.setProperty(InstanceGCPProvider.GCP_PROP_DNS_SUFFIX, "gcp.athenz.cloud");
        System.setProperty(InstanceGCPProvider.GCP_PROP_REGION_NAME, "us-west1");
    }

    @AfterMethod
    public void shutdown() {
        System.clearProperty(InstanceGCPProvider.GCP_PROP_DNS_SUFFIX);
        System.clearProperty(InstanceGCPProvider.GCP_PROP_REGION_NAME);
    }

    @Test
    public void testInitializeDefaults() {
        InstanceGCPProvider provider = new InstanceGCPProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceGCPProvider", null, null);
        assertEquals(provider.getTimeOffsetInMilli(), 300000);
        provider.close();
    }

    @Test
    public void testInitialize() {

        InstanceGCPProvider provider = new InstanceGCPProvider();
        System.setProperty(InstanceGCPProvider.GCP_PROP_BOOT_TIME_OFFSET, "60");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceGCPProvider", null, null);
        assertEquals(provider.getTimeOffsetInMilli(), 60000);
        provider.close();
        System.clearProperty(InstanceGCPProvider.GCP_PROP_BOOT_TIME_OFFSET);
    }

    @Test
    public void testInitializeDNSSuffix() {
        InstanceGCPProvider provider = new InstanceGCPProvider();
        System.clearProperty(InstanceGCPProvider.GCP_PROP_DNS_SUFFIX);
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceGCPProvider", null, null);
        assertTrue(provider.getDnsSuffixes().isEmpty());
        provider.close();

        provider = new InstanceGCPProvider();
        System.setProperty(InstanceGCPProvider.GCP_PROP_DNS_SUFFIX, "");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceGCPProvider", null, null);
        assertTrue(provider.getDnsSuffixes().isEmpty());
        provider.close();

        provider = new InstanceGCPProvider();
        System.setProperty(InstanceGCPProvider.GCP_PROP_DNS_SUFFIX, "athenz1.cloud,athenz2.cloud");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceGCPProvider", null, null);
        assertEquals(provider.getDnsSuffixes().size(), 2);
        assertTrue(provider.getDnsSuffixes().contains("athenz1.cloud"));
        assertTrue(provider.getDnsSuffixes().contains("athenz2.cloud"));
        provider.close();
    }

    @Test
    public void testError() {

        InstanceGCPProvider provider = new InstanceGCPProvider();
        ResourceException exc = provider.error("unable to access");
        assertEquals(exc.getCode(), 403);
        assertEquals(exc.getMessage(), "ResourceException (403): unable to access");
        provider.close();
    }

    @Test
    public void testValidateGCPProject() {

        StringBuilder errMsg = new StringBuilder(256);
        InstanceGCPProvider provider = new InstanceGCPProvider();
        assertTrue(provider.validateGCPProject("1234", "1234", errMsg));
        assertFalse(provider.validateGCPProject("1235", "1234", errMsg));
        provider.close();
    }

    @Test
    public void testGetProviderScheme() {
        InstanceGCPProvider provider = new InstanceGCPProvider();
        assertEquals(provider.getProviderScheme(), InstanceProvider.Scheme.HTTP);
        provider.close();
    }

    @Test
    public void testValidateGCPProvider() {

        StringBuilder errMsg = new StringBuilder(256);
        InstanceGCPProvider provider = new InstanceGCPProvider();
        assertTrue(provider.validateGCPProvider("gcp.gce.us-west1", "us-west1", errMsg));
        assertFalse(provider.validateGCPProvider("gcp.gce", "us-west1", errMsg));
        provider.close();
    }

    @Test
    public void testValidateInstanceId() {

        StringBuilder errMsg = new StringBuilder(256);
        InstanceGCPProvider provider = new InstanceGCPProvider();
        assertTrue(provider.validateGCPInstanceId("1234", "1234", errMsg));
        assertFalse(provider.validateGCPInstanceId("1235", "1234", errMsg));
        provider.close();
    }

    @Test
    public void testValidateIdentityTokenInvalidToken() {
        InstanceGCPProvider provider = new InstanceGCPProvider();

        GCPAttestationData attestationData = new GCPAttestationData();
        GCPDerivedAttestationData derivedAttestationData = new GCPDerivedAttestationData();
        String gcpProject = "gcp-proj1";
        String instanceId = "123";
        StringBuilder errMsg = new StringBuilder(256);

        attestationData.setIdentityToken("abc");
        InstanceGCPUtils gcpUtilsMock = Mockito.mock(InstanceGCPUtils.class);
        Mockito.when(gcpUtilsMock.validateGCPIdentityToken(anyString(), any())).thenReturn(null);
        provider.gcpUtils = gcpUtilsMock;

        assertFalse(provider.validateIdentityToken("gcp.gce.us-west1", attestationData, derivedAttestationData,
                gcpProject, instanceId, true, errMsg));
        provider.close();
    }

    private GoogleIdToken.Payload createPayload(boolean makeAdditional) {
        GoogleIdToken.Payload payload = new GoogleIdToken.Payload();
        payload.setAudience("https://my-zts-server");
        payload.setIssuer("https://accounts.google.com");
        payload.setEmail("my-sa@my-gcp-project.iam.gserviceaccount.com");
        payload.setEmailVerified(true);
        payload.setAuthorizedParty("102023896904281105569");

        if (makeAdditional) {
            Map<String, Map<String, Object>> extras = new ArrayMap<>();
            Map<String, Object> extrasCE = new ArrayMap<>();

            extrasCE.put("instance_creation_timestamp", new BigDecimal(1677459985));
            extrasCE.put("instance_id", "3692465099344887023");
            extrasCE.put("instance_name", "my-vm");
            extrasCE.put("project_id", "my-gcp-project");
            extrasCE.put("project_number", new BigDecimal(1234567890123L));
            extrasCE.put("zone", "us-west1-a");

            extras.put("compute_engine", extrasCE);
            payload.set("google", extras);
        }
        return payload;
    }

    private GoogleIdToken.Payload createRecentPayload(boolean makeAdditional) {
        GoogleIdToken.Payload payload = createPayload(makeAdditional);
        if (makeAdditional) {
            ((Map<String, Map<String, Object>>)payload.get("google")).get("compute_engine")
                    .put("instance_creation_timestamp", new BigDecimal(System.currentTimeMillis() - 4000));
        }
        return payload;
    }

    @Test
    public void testValidateIdentityTokenInvalidProject() {
        InstanceGCPProvider provider = new InstanceGCPProvider();

        GCPAttestationData attestationData = new GCPAttestationData();
        GCPDerivedAttestationData derivedAttestationData = new GCPDerivedAttestationData();
        String gcpProject = "invalid";
        String instanceId = "123";
        StringBuilder errMsg = new StringBuilder(256);

        attestationData.setIdentityToken("abc");
        InstanceGCPUtils gcpUtilsMock = Mockito.mock(InstanceGCPUtils.class);
        Mockito.when(gcpUtilsMock.validateGCPIdentityToken(anyString(), any())).thenReturn(createPayload(true));
        provider.gcpUtils = gcpUtilsMock;

        assertFalse(provider.validateIdentityToken("gcp.gce.us-west1", attestationData, derivedAttestationData,
                gcpProject, instanceId, true, errMsg));
        provider.close();
    }

    @Test
    public void testValidateIdentityTokenIncompleteAttestationData() {
        InstanceGCPProvider provider = new InstanceGCPProvider();

        GCPAttestationData attestationData = new GCPAttestationData();
        GCPDerivedAttestationData derivedAttestationData = new GCPDerivedAttestationData();
        String gcpProject = "my-gcp-project";
        String instanceId = "123";
        StringBuilder errMsg = new StringBuilder(256);

        attestationData.setIdentityToken("abc");
        InstanceGCPUtils gcpUtilsMock = Mockito.mock(InstanceGCPUtils.class);
        Mockito.when(gcpUtilsMock.validateGCPIdentityToken(anyString(), any())).thenReturn(createPayload(false));
        Mockito.when(gcpUtilsMock.getProjectIdFromAttestedData(any())).thenReturn("my-gcp-project");
        provider.gcpUtils = gcpUtilsMock;

        assertTrue(provider.validateIdentityToken("gcp.gce.us-west1", attestationData, derivedAttestationData,
                gcpProject, instanceId, true, errMsg));
        provider.close();
    }

    @Test
    public void testValidateIdentityTokenInvalidProvider() {
        InstanceGCPProvider provider = new InstanceGCPProvider();

        GCPAttestationData attestationData = new GCPAttestationData();
        GCPDerivedAttestationData derivedAttestationData = new GCPDerivedAttestationData();
        String gcpProject = "my-gcp-project";
        String instanceId = "123";
        StringBuilder errMsg = new StringBuilder(256);

        GoogleIdToken.Payload dummyPayload = createPayload(true);
        attestationData.setIdentityToken("abc");
        InstanceGCPUtils gcpUtilsMock = Mockito.mock(InstanceGCPUtils.class);
        Mockito.when(gcpUtilsMock.validateGCPIdentityToken("abc", errMsg)).thenReturn(dummyPayload);
        Mockito.when(gcpUtilsMock.getProjectIdFromAttestedData(any())).thenReturn("my-gcp-project");
        Mockito.when(gcpUtilsMock.getGCPRegionFromZone(any())).thenReturn("us-west1");
        Mockito.doCallRealMethod().when(gcpUtilsMock).populateAttestationData(dummyPayload, derivedAttestationData);
        provider.gcpUtils = gcpUtilsMock;

        assertFalse(provider.validateIdentityToken("gcp.gce", attestationData, derivedAttestationData,
                gcpProject, instanceId, true, errMsg));
        provider.close();
    }

    @Test
    public void testValidateIdentityTokenInvalidInstanceId() {
        InstanceGCPProvider provider = new InstanceGCPProvider();

        GCPAttestationData attestationData = new GCPAttestationData();
        GCPDerivedAttestationData derivedAttestationData = new GCPDerivedAttestationData();
        String gcpProject = "my-gcp-project";
        String instanceId = "123";
        StringBuilder errMsg = new StringBuilder(256);

        GoogleIdToken.Payload dummyPayload = createPayload(true);
        attestationData.setIdentityToken("abc");
        InstanceGCPUtils gcpUtilsMock = Mockito.mock(InstanceGCPUtils.class);
        Mockito.when(gcpUtilsMock.validateGCPIdentityToken("abc", errMsg)).thenReturn(dummyPayload);
        Mockito.when(gcpUtilsMock.getProjectIdFromAttestedData(any())).thenReturn("my-gcp-project");
        Mockito.when(gcpUtilsMock.getGCPRegionFromZone(any())).thenReturn("us-west1");
        Mockito.doCallRealMethod().when(gcpUtilsMock).populateAttestationData(dummyPayload, derivedAttestationData);
        provider.gcpUtils = gcpUtilsMock;

        assertFalse(provider.validateIdentityToken("gcp.gce.us-west1", attestationData, derivedAttestationData,
                gcpProject, instanceId, true, errMsg));
        provider.close();
    }

    @Test
    public void testValidateIdentityTokenBootTime() {
        InstanceGCPProvider provider = new InstanceGCPProvider();
        System.setProperty(InstanceGCPProvider.GCP_PROP_BOOT_TIME_OFFSET, "60");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceGCPProvider", null, null);

        GCPAttestationData attestationData = new GCPAttestationData();
        GCPDerivedAttestationData derivedAttestationData = new GCPDerivedAttestationData();
        String gcpProject = "my-gcp-project";
        String instanceId = "3692465099344887023";
        StringBuilder errMsg = new StringBuilder(256);

        GoogleIdToken.Payload dummyPayload = createPayload(true);
        attestationData.setIdentityToken("abc");
        InstanceGCPUtils gcpUtilsMock = Mockito.mock(InstanceGCPUtils.class);
        Mockito.when(gcpUtilsMock.validateGCPIdentityToken("abc", errMsg)).thenReturn(dummyPayload);
        Mockito.when(gcpUtilsMock.getProjectIdFromAttestedData(any())).thenReturn("my-gcp-project");
        Mockito.when(gcpUtilsMock.getGCPRegionFromZone(any())).thenReturn("us-west1");
        Mockito.doCallRealMethod().when(gcpUtilsMock).populateAttestationData(dummyPayload, derivedAttestationData);
        provider.gcpUtils = gcpUtilsMock;

        assertFalse(provider.validateIdentityToken("gcp.gce.us-west1", attestationData, derivedAttestationData,
                gcpProject, instanceId, true, errMsg));
        provider.close();
    }

    @Test
    public void testValidateIdentityTokenBootTimeZeroOffset() {
        InstanceGCPProvider provider = new InstanceGCPProvider();
        System.setProperty(InstanceGCPProvider.GCP_PROP_BOOT_TIME_OFFSET, "0");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceGCPProvider", null, null);

        GCPAttestationData attestationData = new GCPAttestationData();
        GCPDerivedAttestationData derivedAttestationData = new GCPDerivedAttestationData();
        String gcpProject = "my-gcp-project";
        String instanceId = "3692465099344887023";
        StringBuilder errMsg = new StringBuilder(256);

        GoogleIdToken.Payload dummyPayload = createPayload(true);
        attestationData.setIdentityToken("abc");
        InstanceGCPUtils gcpUtilsMock = Mockito.mock(InstanceGCPUtils.class);
        Mockito.when(gcpUtilsMock.validateGCPIdentityToken("abc", errMsg)).thenReturn(dummyPayload);
        Mockito.when(gcpUtilsMock.getProjectIdFromAttestedData(any())).thenReturn("my-gcp-project");
        Mockito.when(gcpUtilsMock.getGCPRegionFromZone(any())).thenReturn("us-west1");
        Mockito.doCallRealMethod().when(gcpUtilsMock).populateAttestationData(dummyPayload, derivedAttestationData);
        provider.gcpUtils = gcpUtilsMock;

        assertTrue(provider.validateIdentityToken("gcp.gce.us-west1", attestationData, derivedAttestationData,
                gcpProject, instanceId, true, errMsg));

        System.clearProperty(InstanceGCPProvider.GCP_PROP_BOOT_TIME_OFFSET);
        provider.close();
    }

    @Test
    public void testValidateIdentityToken() {
        InstanceGCPProvider provider = new InstanceGCPProvider();
        System.setProperty(InstanceGCPProvider.GCP_PROP_BOOT_TIME_OFFSET, "60");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceGCPProvider", null, null);

        GCPAttestationData attestationData = new GCPAttestationData();
        GCPDerivedAttestationData derivedAttestationData = new GCPDerivedAttestationData();
        String gcpProject = "my-gcp-project";
        String instanceId = "3692465099344887023";
        StringBuilder errMsg = new StringBuilder(256);

        GoogleIdToken.Payload dummyPayload = createRecentPayload(true);
        attestationData.setIdentityToken("abc");
        InstanceGCPUtils gcpUtilsMock = Mockito.mock(InstanceGCPUtils.class);
        Mockito.when(gcpUtilsMock.validateGCPIdentityToken("abc", errMsg)).thenReturn(dummyPayload);
        Mockito.when(gcpUtilsMock.getProjectIdFromAttestedData(any())).thenReturn("my-gcp-project");
        Mockito.when(gcpUtilsMock.getGCPRegionFromZone(any())).thenReturn("us-west1");
        Mockito.doCallRealMethod().when(gcpUtilsMock).populateAttestationData(dummyPayload, derivedAttestationData);
        provider.gcpUtils = gcpUtilsMock;

        assertTrue(provider.validateIdentityToken("gcp.gce.us-west1", attestationData, derivedAttestationData,
                gcpProject, instanceId, true, errMsg));

        System.clearProperty(InstanceGCPProvider.GCP_PROP_BOOT_TIME_OFFSET);
        provider.close();
    }

    @Test
    public void testConfirmInstanceEmptyProject() {

        InstanceGCPProvider provider = new InstanceGCPProvider();
        System.setProperty(InstanceGCPProvider.GCP_PROP_BOOT_TIME_OFFSET, "60");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceGCPProvider", null, null);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData("{\"identityToken\": \"abc\"}");
        confirmation.setDomain("athenz");
        confirmation.setService("gcp");
        Map<String, String> attrs = new HashMap<>();
        attrs.put(ZTS_INSTANCE_GCP_PROJECT, "");
        confirmation.setAttributes(attrs);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (Exception ignored) {
        }

        System.clearProperty(InstanceGCPProvider.GCP_PROP_BOOT_TIME_OFFSET);
        provider.close();
    }

    @Test
    public void testConfirmInstanceInvalidSANDNS() {

        InstanceGCPProvider provider = new InstanceGCPProvider();
        System.setProperty(InstanceGCPProvider.GCP_PROP_BOOT_TIME_OFFSET, "60");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceGCPProvider", null, null);


        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData("{\"identityToken\": \"abc\"}");
        confirmation.setDomain("athenz");
        confirmation.setService("gcp");
        Map<String, String> attrs = new HashMap<>();
        attrs.put(ZTS_INSTANCE_GCP_PROJECT, "my-gcp-project");
        confirmation.setAttributes(attrs);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (Exception ignored) {}

        System.clearProperty(InstanceGCPProvider.GCP_PROP_BOOT_TIME_OFFSET);
        provider.close();
    }

    @Test
    public void testConfirmInstanceInvalidAttestationData() {

        InstanceGCPProvider provider = new InstanceGCPProvider();
        System.setProperty(InstanceGCPProvider.GCP_PROP_BOOT_TIME_OFFSET, "60");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceGCPProvider", null, null);

        InstanceGCPUtils gcpUtilsMock = Mockito.mock(InstanceGCPUtils.class);
        Mockito.when(gcpUtilsMock.validateGCPIdentityToken(anyString(), any(StringBuilder.class))).thenReturn(null);
        provider.gcpUtils = gcpUtilsMock;

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData("{\"identityToken\": \"abc\"}");
        confirmation.setDomain("my.domain");
        confirmation.setService("my-service");
        confirmation.setProvider("gcp.us-west1");

        Map<String, String> attrs = new HashMap<>();
        attrs.put(ZTS_INSTANCE_GCP_PROJECT, "my-gcp-project");
        attrs.put(ZTS_INSTANCE_SAN_DNS, "my-service.my-domain.gcp.athenz.cloud,3692465099344887023.instanceid.athenz.gcp.athenz.cloud");
        attrs.put(ZTS_INSTANCE_SAN_URI, "spiffe://my-domain/sa/my-service");
        confirmation.setAttributes(attrs);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch(Exception ignored) {}

        System.clearProperty(InstanceGCPProvider.GCP_PROP_BOOT_TIME_OFFSET);
        provider.close();
    }

    @Test
    public void testConfirmInstanceServiceMismatch() {

        InstanceGCPProvider provider = new InstanceGCPProvider();
        System.setProperty(InstanceGCPProvider.GCP_PROP_BOOT_TIME_OFFSET, "60");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceGCPProvider", null, null);

        GoogleIdToken.Payload dummyPayload = createRecentPayload(true);
        InstanceGCPUtils gcpUtilsMock = Mockito.mock(InstanceGCPUtils.class);
        Mockito.when(gcpUtilsMock.validateGCPIdentityToken(anyString(), any(StringBuilder.class))).thenReturn(dummyPayload);
        Mockito.when(gcpUtilsMock.getProjectIdFromAttestedData(any())).thenReturn("my-gcp-project");
        Mockito.when(gcpUtilsMock.getGCPRegionFromZone(any())).thenReturn("us-west1");
        Mockito.when(gcpUtilsMock.getServiceNameFromAttestedData(any())).thenReturn("my-gcp-project.my-service");
        Mockito.doCallRealMethod().when(gcpUtilsMock).populateAttestationData(any(GoogleIdToken.Payload.class), any(GCPDerivedAttestationData.class));
        provider.gcpUtils = gcpUtilsMock;

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData("{\"identityToken\": \"abc\"}");
        confirmation.setDomain("my.domain");
        confirmation.setService("my-evil-service");
        confirmation.setProvider("gcp.us-west1");

        Map<String, String> attrs = new HashMap<>();
        attrs.put(ZTS_INSTANCE_GCP_PROJECT, "my-gcp-project");
        attrs.put(ZTS_INSTANCE_SAN_DNS, "my-evil-service.my-domain.gcp.athenz.cloud,3692465099344887023.instanceid.athenz.gcp.athenz.cloud");
        attrs.put(ZTS_INSTANCE_SAN_URI, "spiffe://my-domain/sa/my-evil-service");
        confirmation.setAttributes(attrs);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch(Exception ignored) {}

        System.clearProperty(InstanceGCPProvider.GCP_PROP_BOOT_TIME_OFFSET);
        provider.close();
    }
    @Test
    public void testConfirmInstance() {

        InstanceGCPProvider provider = new InstanceGCPProvider();
        System.setProperty(InstanceGCPProvider.GCP_PROP_BOOT_TIME_OFFSET, "60");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceGCPProvider", null, null);

        GoogleIdToken.Payload dummyPayload = createRecentPayload(true);
        InstanceGCPUtils gcpUtilsMock = Mockito.mock(InstanceGCPUtils.class);
        Mockito.when(gcpUtilsMock.validateGCPIdentityToken(anyString(), any(StringBuilder.class))).thenReturn(dummyPayload);
        Mockito.when(gcpUtilsMock.getProjectIdFromAttestedData(any())).thenReturn("my-gcp-project");
        Mockito.when(gcpUtilsMock.getGCPRegionFromZone(any())).thenReturn("us-west1");
        Mockito.when(gcpUtilsMock.getServiceNameFromAttestedData(any())).thenReturn("my-gcp-project.my-service");
        Mockito.doCallRealMethod().when(gcpUtilsMock).populateAttestationData(any(GoogleIdToken.Payload.class), any(GCPDerivedAttestationData.class));
        provider.gcpUtils = gcpUtilsMock;

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData("{\"identityToken\": \"abc\"}");
        confirmation.setDomain("my.domain");
        confirmation.setService("my-service");
        confirmation.setProvider("gcp.us-west1");

        Map<String, String> attrs = new HashMap<>();
        attrs.put(ZTS_INSTANCE_GCP_PROJECT, "my-gcp-project");
        attrs.put(ZTS_INSTANCE_SAN_DNS, "my-service.my-domain.gcp.athenz.cloud,3692465099344887023.instanceid.athenz.gcp.athenz.cloud");
        attrs.put(ZTS_INSTANCE_SAN_URI, "spiffe://my-domain/sa/my-service");
        confirmation.setAttributes(attrs);

        provider.confirmInstance(confirmation);

        assertEquals(confirmation.getAttributes().size(), 1);
        assertEquals(confirmation.getAttributes().get(InstanceProvider.ZTS_CERT_SSH), "true");


        System.clearProperty(InstanceGCPProvider.GCP_PROP_BOOT_TIME_OFFSET);
        provider.close();
    }

    @Test
    public void testConfirmInstanceNoAdditionalMetadata() {

        InstanceGCPProvider provider = new InstanceGCPProvider();
        System.setProperty(InstanceGCPProvider.GCP_PROP_BOOT_TIME_OFFSET, "60");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceGCPProvider", null, null);

        GoogleIdToken.Payload dummyPayload = createRecentPayload(false);
        InstanceGCPUtils gcpUtilsMock = Mockito.mock(InstanceGCPUtils.class);
        Mockito.when(gcpUtilsMock.validateGCPIdentityToken(anyString(), any(StringBuilder.class))).thenReturn(dummyPayload);
        Mockito.when(gcpUtilsMock.getProjectIdFromAttestedData(any())).thenReturn("my-gcp-project");
        Mockito.when(gcpUtilsMock.getGCPRegionFromZone(any())).thenReturn("us-west1");
        Mockito.when(gcpUtilsMock.getServiceNameFromAttestedData(any())).thenReturn("my-gcp-project.my-service");
        Mockito.doCallRealMethod().when(gcpUtilsMock).populateAttestationData(any(GoogleIdToken.Payload.class), any(GCPDerivedAttestationData.class));
        provider.gcpUtils = gcpUtilsMock;

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData("{\"identityToken\": \"abc\"}");
        confirmation.setDomain("my.domain");
        confirmation.setService("my-service");
        confirmation.setProvider("gcp.us-west1");

        Map<String, String> attrs = new HashMap<>();
        attrs.put(ZTS_INSTANCE_GCP_PROJECT, "my-gcp-project");
        attrs.put(ZTS_INSTANCE_SAN_DNS, "my-service.my-domain.gcp.athenz.cloud,3692465099344887023.instanceid.athenz.gcp.athenz.cloud");
        attrs.put(ZTS_INSTANCE_SAN_URI, "spiffe://my-domain/sa/my-service");
        confirmation.setAttributes(attrs);

        provider.confirmInstance(confirmation);

        assertEquals(confirmation.getAttributes().size(), 2);
        assertEquals(confirmation.getAttributes().get(InstanceProvider.ZTS_CERT_SSH), "false");
        assertEquals(confirmation.getAttributes().get(InstanceProvider.ZTS_CERT_EXPIRY_TIME), "10080");

        System.clearProperty(InstanceGCPProvider.GCP_PROP_BOOT_TIME_OFFSET);
        provider.close();
    }

    @Test
    public void testRefreshInstance() {

        InstanceGCPProvider provider = new InstanceGCPProvider();
        System.setProperty(InstanceGCPProvider.GCP_PROP_BOOT_TIME_OFFSET, "60");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceGCPProvider", null, null);

        GoogleIdToken.Payload dummyPayload = createRecentPayload(true);
        InstanceGCPUtils gcpUtilsMock = Mockito.mock(InstanceGCPUtils.class);
        Mockito.when(gcpUtilsMock.validateGCPIdentityToken(anyString(), any(StringBuilder.class))).thenReturn(dummyPayload);
        Mockito.when(gcpUtilsMock.getProjectIdFromAttestedData(any())).thenReturn("my-gcp-project");
        Mockito.when(gcpUtilsMock.getGCPRegionFromZone(any())).thenReturn("us-west1");
        Mockito.when(gcpUtilsMock.getServiceNameFromAttestedData(any())).thenReturn("my-gcp-project.my-service");
        Mockito.doCallRealMethod().when(gcpUtilsMock).populateAttestationData(any(GoogleIdToken.Payload.class), any(GCPDerivedAttestationData.class));
        provider.gcpUtils = gcpUtilsMock;

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData("{\"identityToken\": \"abc\"}");
        confirmation.setDomain("my.domain");
        confirmation.setService("my-service");
        confirmation.setProvider("gcp.us-west1");

        Map<String, String> attrs = new HashMap<>();
        attrs.put(ZTS_INSTANCE_GCP_PROJECT, "my-gcp-project");
        attrs.put(ZTS_INSTANCE_ID, "3692465099344887023");
        attrs.put(ZTS_INSTANCE_SAN_DNS, "my-service.my-domain.gcp.athenz.cloud,3692465099344887023.instanceid.athenz.gcp.athenz.cloud");
        attrs.put(ZTS_INSTANCE_SAN_URI, "spiffe://my-domain/sa/my-service");

        confirmation.setAttributes(attrs);

        provider.refreshInstance(confirmation);

        assertEquals(confirmation.getAttributes().size(), 1);
        assertEquals(confirmation.getAttributes().get(InstanceProvider.ZTS_CERT_SSH), "true");


        System.clearProperty(InstanceGCPProvider.GCP_PROP_BOOT_TIME_OFFSET);
        provider.close();
    }

    @Test
    public void testRefreshInstanceNoAttestationData() {

        InstanceGCPProvider provider = new InstanceGCPProvider();
        System.setProperty(InstanceGCPProvider.GCP_PROP_BOOT_TIME_OFFSET, "60");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceGCPProvider", null, null);

        GoogleIdToken.Payload dummyPayload = createRecentPayload(true);
        InstanceGCPUtils gcpUtilsMock = Mockito.mock(InstanceGCPUtils.class);
        Mockito.when(gcpUtilsMock.validateGCPIdentityToken(anyString(), any(StringBuilder.class))).thenReturn(dummyPayload);
        Mockito.when(gcpUtilsMock.getProjectIdFromAttestedData(any())).thenReturn("my-gcp-project");
        Mockito.when(gcpUtilsMock.getGCPRegionFromZone(any())).thenReturn("us-west1");
        Mockito.when(gcpUtilsMock.getServiceNameFromAttestedData(any())).thenReturn("my-gcp-project.my-service");
        Mockito.doCallRealMethod().when(gcpUtilsMock).populateAttestationData(any(GoogleIdToken.Payload.class), any(GCPDerivedAttestationData.class));
        provider.gcpUtils = gcpUtilsMock;

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("my.domain");
        confirmation.setService("my-service");
        confirmation.setProvider("gcp.us-west1");

        Map<String, String> attrs = new HashMap<>();
        attrs.put(ZTS_INSTANCE_GCP_PROJECT, "my-gcp-project");
        attrs.put(ZTS_INSTANCE_ID, "3692465099344887023");
        attrs.put(ZTS_INSTANCE_SAN_DNS, "my-service.my-domain.gcp.athenz.cloud,3692465099344887023.instanceid.athenz.gcp.athenz.cloud");
        attrs.put(ZTS_INSTANCE_SAN_URI, "spiffe://my-domain/sa/my-service");

        confirmation.setAttributes(attrs);

        try {
            provider.refreshInstance(confirmation);
            fail();
        } catch (Exception ignored) {}

        System.clearProperty(InstanceGCPProvider.GCP_PROP_BOOT_TIME_OFFSET);
        provider.close();
    }

    @Test
    public void testRefreshInstanceEmptyProject() {

        InstanceGCPProvider provider = new InstanceGCPProvider();
        System.setProperty(InstanceGCPProvider.GCP_PROP_BOOT_TIME_OFFSET, "60");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceGCPProvider", null, null);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData("{\"identityToken\": \"abc\"}");
        confirmation.setDomain("athenz");
        confirmation.setService("gcp");
        Map<String, String> attrs = new HashMap<>();
        attrs.put(ZTS_INSTANCE_GCP_PROJECT, "");
        confirmation.setAttributes(attrs);

        try {
            provider.refreshInstance(confirmation);
            fail();
        } catch (Exception ignored) {
        }

        System.clearProperty(InstanceGCPProvider.GCP_PROP_BOOT_TIME_OFFSET);
        provider.close();
    }

    @Test
    public void testRefreshInstanceNoInstanceId() {

        InstanceGCPProvider provider = new InstanceGCPProvider();
        System.setProperty(InstanceGCPProvider.GCP_PROP_BOOT_TIME_OFFSET, "60");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceGCPProvider", null, null);

        GoogleIdToken.Payload dummyPayload = createRecentPayload(true);
        InstanceGCPUtils gcpUtilsMock = Mockito.mock(InstanceGCPUtils.class);
        Mockito.when(gcpUtilsMock.validateGCPIdentityToken(anyString(), any(StringBuilder.class))).thenReturn(dummyPayload);
        Mockito.when(gcpUtilsMock.getProjectIdFromAttestedData(any())).thenReturn("my-gcp-project");
        Mockito.when(gcpUtilsMock.getGCPRegionFromZone(any())).thenReturn("us-west1");
        Mockito.when(gcpUtilsMock.getServiceNameFromAttestedData(any())).thenReturn("my-gcp-project.my-service");
        Mockito.doCallRealMethod().when(gcpUtilsMock).populateAttestationData(any(GoogleIdToken.Payload.class), any(GCPDerivedAttestationData.class));
        provider.gcpUtils = gcpUtilsMock;

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData("{\"identityToken\": \"abc\"}");
        confirmation.setDomain("my.domain");
        confirmation.setService("my-service");
        confirmation.setProvider("gcp.us-west1");

        Map<String, String> attrs = new HashMap<>();
        attrs.put(ZTS_INSTANCE_GCP_PROJECT, "my-gcp-project");
        attrs.put(ZTS_INSTANCE_SAN_DNS, "my-service.my-domain.gcp.athenz.cloud,3692465099344887023.instanceid.athenz.gcp.athenz.cloud");
        attrs.put(ZTS_INSTANCE_SAN_URI, "spiffe://my-domain/sa/my-service");

        confirmation.setAttributes(attrs);

        try {
            provider.refreshInstance(confirmation);
            fail();
        } catch (Exception ignored) {}

        System.clearProperty(InstanceGCPProvider.GCP_PROP_BOOT_TIME_OFFSET);
        provider.close();
    }
}