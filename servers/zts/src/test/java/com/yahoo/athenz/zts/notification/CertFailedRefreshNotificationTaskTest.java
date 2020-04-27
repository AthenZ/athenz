/*
 *  Copyright 2020 Verizon Media
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

package com.yahoo.athenz.zts.notification;

import com.yahoo.athenz.common.server.dns.HostnameResolver;
import com.yahoo.athenz.common.server.notification.Notification;
import com.yahoo.athenz.common.server.cert.X509CertRecord;
import com.yahoo.athenz.common.server.notification.NotificationEmail;
import com.yahoo.athenz.zms.DomainData;
import com.yahoo.athenz.zts.cert.InstanceCertManager;
import com.yahoo.athenz.zts.store.DataStore;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.sql.Timestamp;
import java.util.*;

import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.*;
import static com.yahoo.athenz.zts.ZTSConsts.ZTS_PROP_NOTIFICATION_CERT_FAIL_PROVIDER_LIST;
import static org.mockito.ArgumentMatchers.*;
import static org.testng.Assert.*;
import static org.testng.Assert.assertFalse;
import static org.testng.AssertJUnit.assertEquals;

public class CertFailedRefreshNotificationTaskTest {
    private InstanceCertManager instanceCertManager;
    private DataStore dataStore;
    private HostnameResolver hostnameResolver;
    private final String userDomainPrefix = "user.";
    private final String serverName = "testServer";

    @BeforeClass
    public void setup() {
        instanceCertManager = Mockito.mock(InstanceCertManager.class);
        dataStore = Mockito.mock(DataStore.class);
        hostnameResolver = Mockito.mock(HostnameResolver.class);
    }

    @Test
    public void testNoProviders() {
        Date currentDate = new Date();
        List<X509CertRecord> records = new ArrayList<>();

        // Create 6 records, each in it's own domain (domain0, domain1... domain5)
        for (int i = 0; i < 6; ++i) {
            X509CertRecord record = getMockX509CertRecord(currentDate, i);
            records.add(record);
            NotificationTestsCommon.mockDomainData(i, dataStore);
        }

        Mockito.when(instanceCertManager.getUnrefreshedCertsNotifications(eq(serverName), anyString())).thenReturn(records);
        CertFailedRefreshNotificationTask certFailedRefreshNotificationTask = new CertFailedRefreshNotificationTask(
                instanceCertManager,
                dataStore,
                hostnameResolver,
                userDomainPrefix,
                serverName);

        List<Notification> notifications = certFailedRefreshNotificationTask.getNotifications();
        assertEquals(0, notifications.size());
    }

    @Test
    public void testSeveralProviders() {
        Date currentDate = new Date();
        List<X509CertRecord> records = new ArrayList<>();

        Mockito.when(hostnameResolver.isValidHostname(anyString())).thenReturn(true);

        // Configure 3 providers in property
        System.setProperty(ZTS_PROP_NOTIFICATION_CERT_FAIL_PROVIDER_LIST, "provider1, provider2, provider3");

        // Create 7 records, each in it's own domain (domain0, domain1... domain6)
        for (int i = 0; i < 7; ++i) {
            X509CertRecord record = getMockX509CertRecord(currentDate, i);
            records.add(record);
            NotificationTestsCommon.mockDomainData(i, dataStore);
        }

        // Set one record in provider1, two records in provider2 and three records in provider3
        records.get(0).setProvider("provider1");
        records.get(1).setProvider("provider2");
        records.get(2).setProvider("provider2");
        records.get(3).setProvider("provider3");
        records.get(4).setProvider("provider3");
        records.get(5).setProvider("provider3");

        // Set one record in a provider not configured in properties (shouldn't be retrieved)
        records.get(6).setProvider("providerNotInProperty");

        Mockito.when(instanceCertManager.getUnrefreshedCertsNotifications(eq(serverName), eq("provider1")))
                .thenReturn(records.subList(0, 1));
        Mockito.when(instanceCertManager.getUnrefreshedCertsNotifications(eq(serverName), eq("provider2")))
                .thenReturn(records.subList(1, 3));
        Mockito.when(instanceCertManager.getUnrefreshedCertsNotifications(eq(serverName), eq("provider3")))
                .thenReturn(records.subList(3, 6));
        Mockito.when(instanceCertManager.getUnrefreshedCertsNotifications(eq(serverName), eq("providerNotInProperty")))
                .thenReturn(records.subList(6, 7));

        CertFailedRefreshNotificationTask certFailedRefreshNotificationTask = new CertFailedRefreshNotificationTask(
                instanceCertManager,
                dataStore,
                hostnameResolver,
                userDomainPrefix,
                serverName);

        List<Notification> notifications = certFailedRefreshNotificationTask.getNotifications();
        assertEquals(6, notifications.size());
        notifications.sort(Comparator.comparing(notif -> notif.getDetails().get("unrefreshedCerts")));
        // Assert one records for provider1:
        String expectedDetail = "domain0.service0;provider1;instanceID0;" + new Timestamp(currentDate.getTime()) + ";;hostName0";
        assertEquals(expectedDetail, notifications.get(0).getDetails().get("unrefreshedCerts"));

        // Assert two records for provider2:
        expectedDetail = "domain1.service1;provider2;instanceID1;" + new Timestamp(currentDate.getTime()) + ";;hostName1";
        assertEquals(expectedDetail, notifications.get(1).getDetails().get("unrefreshedCerts"));

        expectedDetail = "domain2.service2;provider2;instanceID2;" + new Timestamp(currentDate.getTime()) + ";;hostName2";
        assertEquals(expectedDetail, notifications.get(2).getDetails().get("unrefreshedCerts"));

        // Assert three records for provider3:
        expectedDetail = "domain3.service3;provider3;instanceID3;" + new Timestamp(currentDate.getTime()) + ";;hostName3";
        assertEquals(expectedDetail, notifications.get(3).getDetails().get("unrefreshedCerts"));

        expectedDetail = "domain4.service4;provider3;instanceID4;" + new Timestamp(currentDate.getTime()) + ";;hostName4";
        assertEquals(expectedDetail, notifications.get(4).getDetails().get("unrefreshedCerts"));

        expectedDetail = "domain5.service5;provider3;instanceID5;" + new Timestamp(currentDate.getTime()) + ";;hostName5";
        assertEquals(expectedDetail, notifications.get(5).getDetails().get("unrefreshedCerts"));

        System.clearProperty(ZTS_PROP_NOTIFICATION_CERT_FAIL_PROVIDER_LIST);
    }

    @Test
    public void testValidHosts() {
        Date currentDate = new Date();
        List<X509CertRecord> records = new ArrayList<>();
        System.setProperty(ZTS_PROP_NOTIFICATION_CERT_FAIL_PROVIDER_LIST, "provider");

        // Create 6 mock records. Only even records host are valid
        boolean isValidHost = true;
        for (int i = 0; i < 6; ++i) {
            X509CertRecord record = getMockX509CertRecord(currentDate, i);
            records.add(record);
            NotificationTestsCommon.mockDomainData(i, dataStore);
            Mockito.when(hostnameResolver.isValidHostname(eq("hostName" + i))).thenReturn(isValidHost);
            isValidHost = !isValidHost;
        }

        // Make a 7th record with no host (but make it valid)
        X509CertRecord record = getMockX509CertRecord(currentDate, 7);
        record.setHostName(null);
        records.add(record);
        NotificationTestsCommon.mockDomainData(7, dataStore);
        Mockito.when(hostnameResolver.isValidHostname(eq(null))).thenReturn(true);

        Mockito.when(instanceCertManager.getUnrefreshedCertsNotifications(eq(serverName), anyString())).thenReturn(records);
        CertFailedRefreshNotificationTask certFailedRefreshNotificationTask = new CertFailedRefreshNotificationTask(
                instanceCertManager,
                dataStore,
                hostnameResolver,
                userDomainPrefix,
                serverName);

        List<Notification> notifications = certFailedRefreshNotificationTask.getNotifications();
        assertEquals(4, notifications.size());
        assertEquals("domain7", notifications.get(0).getDetails().get("domain"));
        assertEquals("domain4", notifications.get(1).getDetails().get("domain"));
        assertEquals("domain2", notifications.get(2).getDetails().get("domain"));
        assertEquals("domain0", notifications.get(3).getDetails().get("domain"));

        System.clearProperty(ZTS_PROP_NOTIFICATION_CERT_FAIL_PROVIDER_LIST);
    }

    @Test
    public void testNoValidRecipient() {
        Date currentDate = new Date();
        List<X509CertRecord> records = new ArrayList<>();
        System.setProperty(ZTS_PROP_NOTIFICATION_CERT_FAIL_PROVIDER_LIST, "provider");

        X509CertRecord record = getMockX509CertRecord(currentDate, 1);
        records.add(record);

        String domainName = "domain1";
        Mockito.when(dataStore.getDomainData(eq(domainName))).thenReturn(new DomainData());
        Mockito.when(hostnameResolver.isValidHostname(eq("hostName1"))).thenReturn(true);

        Mockito.when(instanceCertManager.getUnrefreshedCertsNotifications(eq(serverName), anyString())).thenReturn(records);
        CertFailedRefreshNotificationTask certFailedRefreshNotificationTask = new CertFailedRefreshNotificationTask(
                instanceCertManager,
                dataStore,
                hostnameResolver,
                userDomainPrefix,
                serverName);

        List<Notification> notifications = certFailedRefreshNotificationTask.getNotifications();
        assertEquals(new ArrayList<>(), notifications);

        System.clearProperty(ZTS_PROP_NOTIFICATION_CERT_FAIL_PROVIDER_LIST);

    }

    @Test
    public void testNoUnrefreshedCerts() {
        Mockito.when(instanceCertManager.getUnrefreshedCertsNotifications(eq(serverName), anyString())).thenReturn(new ArrayList<>());
        CertFailedRefreshNotificationTask certFailedRefreshNotificationTask = new CertFailedRefreshNotificationTask(
                instanceCertManager,
                dataStore,
                hostnameResolver,
                userDomainPrefix,
                serverName);
        List<Notification> notifications = certFailedRefreshNotificationTask.getNotifications();
        assertEquals(new ArrayList<>(), notifications);
    }

    @Test
    public void testNotificationsByDomain() {
        Date currentDate = new Date();
        List<X509CertRecord> records = new ArrayList<>();
        System.setProperty(ZTS_PROP_NOTIFICATION_CERT_FAIL_PROVIDER_LIST, "provider");

        // Create 6 records, each in it's own domain (domain0, domain1... domain5)
        for (int i = 0; i < 6; ++i) {
            X509CertRecord record = getMockX509CertRecord(currentDate, i);
            records.add(record);
            NotificationTestsCommon.mockDomainData(i, dataStore);
        }

        // Now add one record to domain 0 and one record to domain 5
        Mockito.when(hostnameResolver.isValidHostname(any())).thenReturn(true);
        X509CertRecord recordDomain0 = getMockX509CertRecord(currentDate, 0);
        recordDomain0.setHostName("secondHostName0");
        X509CertRecord recordDomain5 = getMockX509CertRecord(currentDate, 5);
        recordDomain5.setHostName("secondHostName5");
        records.add(recordDomain0);
        records.add(recordDomain5);

        Mockito.when(instanceCertManager.getUnrefreshedCertsNotifications(eq(serverName), anyString())).thenReturn(records);
        CertFailedRefreshNotificationTask certFailedRefreshNotificationTask = new CertFailedRefreshNotificationTask(
                instanceCertManager,
                dataStore,
                hostnameResolver,
                userDomainPrefix,
                serverName);

        List<Notification> notifications = certFailedRefreshNotificationTask.getNotifications();
        assertEquals(6, notifications.size());
        // Assert 2 records for domain5 and domain0:
        String twoRecordsDomain5 = "domain5.service5;provider;instanceID5;" + new Timestamp(currentDate.getTime()) + ";;hostName5|" +
                "domain5.service5;provider;instanceID5;" + new Timestamp(currentDate.getTime()) + ";;secondHostName5";
        assertEquals(twoRecordsDomain5, notifications.get(1).getDetails().get("unrefreshedCerts"));
        String twoRecordsDomain0 = "domain0.service0;provider;instanceID0;" + new Timestamp(currentDate.getTime()) + ";;hostName0|" +
                "domain0.service0;provider;instanceID0;" + new Timestamp(currentDate.getTime()) + ";;secondHostName0";
        assertEquals(twoRecordsDomain0, notifications.get(4).getDetails().get("unrefreshedCerts"));

        // Assert other domains only have 1 record:
        String oneRecordDomain1 = "domain1.service1;provider;instanceID1;" + new Timestamp(currentDate.getTime()) + ";;hostName1";
        assertEquals(oneRecordDomain1, notifications.get(5).getDetails().get("unrefreshedCerts"));

        System.clearProperty(ZTS_PROP_NOTIFICATION_CERT_FAIL_PROVIDER_LIST);
    }

    private X509CertRecord getMockX509CertRecord(Date date, int recordId) {
        X509CertRecord record = new X509CertRecord();
        record.setHostName("hostName" + recordId);
        record.setCurrentTime(date);
        record.setInstanceId("instanceID" + recordId);
        record.setProvider("provider");
        record.setService("domain" + recordId + ".service" + recordId);
        return record;
    }

    @Test
    public void testDescription() {
        CertFailedRefreshNotificationTask certFailedRefreshNotificationTask = new CertFailedRefreshNotificationTask(
                instanceCertManager,
                dataStore,
                hostnameResolver,
                userDomainPrefix,
                serverName);

        String description = certFailedRefreshNotificationTask.getDescription();
        assertEquals("certificate failed refresh notification", description);
    }

    @Test
    public void testGetEmailBody() {
        System.setProperty("athenz.notification_workflow_url", "https://athenz.example.com/workflow");
        System.setProperty("athenz.notification_support_text", "#Athenz slack channel");
        System.setProperty("athenz.notification_support_url", "https://link.to.athenz.channel.com");

        Map<String, String> details = new HashMap<>();
        details.put("domain", "dom1");
        details.put("role", "role1");
        details.put("member", "user.member1");
        details.put("reason", "test reason");
        details.put("requester", "user.requester");
        details.put(NOTIFICATION_DETAILS_UNREFRESHED_CERTS,
                "domain0.service0;provider;instanceID0;Sun Mar 15 15:08:07 IST 2020;;hostName0|" +
                        "domain.bad;instanceID0;Sun Mar 15 15:08:07 IST 2020;;hostBad|" + // bad entry with missing provider
                        "domain0.service0;provider;instanceID0;Sun Mar 15 15:08:07 IST 2020;;secondHostName0");

        Notification notification = new Notification();
        notification.setDetails(details);
        CertFailedRefreshNotificationTask.CertFailedRefreshNotificationToEmailConverter converter = new CertFailedRefreshNotificationTask.CertFailedRefreshNotificationToEmailConverter();
        NotificationEmail notificationAsEmail = converter.getNotificationAsEmail(notification);

        String body = notificationAsEmail.getBody();
        assertNotNull(body);
        assertTrue(body.contains("domain0.service0"));
        assertTrue(body.contains("hostName0"));
        assertTrue(body.contains("secondHostName0"));
        assertTrue(body.contains("instanceID0"));
        assertTrue(body.contains("Sun Mar 15 15:08:07 IST 2020"));

        // make sure the bad entries are not included
        assertFalse(body.contains("domain.bad"));
        assertFalse(body.contains("hostBad"));

        // Make sure support text and url do appear

        assertTrue(body.contains("slack"));
        assertTrue(body.contains("link.to.athenz.channel.com"));

        System.clearProperty("athenz.notification_workflow_url");
        System.clearProperty("notification_support_text");
        System.clearProperty("notification_support_url");
    }

    @Test
    public void getEmailSubject() {
        Notification notification = new Notification();
        CertFailedRefreshNotificationTask.CertFailedRefreshNotificationToEmailConverter converter = new CertFailedRefreshNotificationTask.CertFailedRefreshNotificationToEmailConverter();
        NotificationEmail notificationAsEmail = converter.getNotificationAsEmail(notification);
        String subject = notificationAsEmail.getSubject();
        Assert.assertEquals(subject, "Athenz Unrefreshed Certificates Notification");
    }
}
