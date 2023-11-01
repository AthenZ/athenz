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

package com.yahoo.athenz.zts.notification;

import com.yahoo.athenz.common.server.dns.HostnameResolver;
import com.yahoo.athenz.common.server.notification.Notification;
import com.yahoo.athenz.common.server.cert.X509CertRecord;
import com.yahoo.athenz.common.server.notification.NotificationEmail;
import com.yahoo.athenz.common.server.notification.NotificationMetric;
import com.yahoo.athenz.common.server.notification.NotificationToEmailConverterCommon;
import com.yahoo.athenz.zms.DomainData;
import com.yahoo.athenz.zms.TagValueList;
import com.yahoo.athenz.zts.ZTSTestUtils;
import com.yahoo.athenz.zts.cert.InstanceCertManager;
import com.yahoo.athenz.zts.store.DataStore;
import com.yahoo.rdl.Timestamp;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.*;

import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.*;
import static com.yahoo.athenz.common.server.notification.impl.MetricNotificationService.*;
import static com.yahoo.athenz.zts.ZTSConsts.ZTS_PROP_NOTIFICATION_CERT_FAIL_IGNORED_SERVICES_LIST;
import static com.yahoo.athenz.zts.ZTSConsts.ZTS_PROP_NOTIFICATION_CERT_FAIL_PROVIDER_LIST;
import static org.mockito.ArgumentMatchers.*;
import static org.testng.Assert.*;
import static org.testng.Assert.assertFalse;
import static org.testng.AssertJUnit.assertEquals;

public class CertFailedRefreshNotificationTaskTest {
    private InstanceCertManager instanceCertManager;
    private NotificationToEmailConverterCommon notificationToEmailConverterCommon;
    private DataStore dataStore;
    private HostnameResolver hostnameResolver;
    private final String userDomainPrefix = "user.";
    private final String serverName = "testServer";
    private final int httpsPort = 4443;
    private final String htmlSeveralRecords =
            "<div class=\"athenz-wrapper\">\n" +
                    "    <div class=\"mbrapproval unrefreshedcerts\">\n" +
                    "        <div class=\"logo\">\n" +
                    "            <img src=\"cid:logo\" class=\"athenzlogowhite\" alt=\"Athenz logo\"/>\n" +
                    "        </div>\n" +
                    "        <div class=\"hdr\">Unrefreshed Certificates Details</div>\n" +
                    "        <div class=\"bt\">You have one or more certificates that failed to refresh in your Athenz domain <b>dom1</b>:</div>\n" +
                    "        <hr>\n" +
                    "        <table id=\"t02\">\n" +
                    "            <thead>\n" +
                    "                <tr>\n" +
                    "                    <th class=\"ch\">SERVICE</th>\n" +
                    "                    <th class=\"ch\">PROVIDER</th>\n" +
                    "                    <th class=\"ch\">INSTANCE ID</th>\n" +
                    "                    <th class=\"ch\">UPDATE TIME</th>\n" +
                    "                    <th class=\"ch\">EXPIRATION TIME</th>\n" +
                    "                    <th class=\"ch\">HOSTNAME</th>\n" +
                    "                </tr>\n" +
                    "            </thead>\n" +
                    "            <tbody><tr><td class=\"cv\">service0</td><td class=\"cv\">provider</td><td class=\"cv\">instanceID0</td><td class=\"cv\">Sun Mar 15 15:08:07 IST 2020</td><td class=\"cv\"></td><td class=\"cv\">hostName0</td></tr>\n" +
                    "<tr><td class=\"cv\">service0</td><td class=\"cv\">provider</td><td class=\"cv\">instanceID0</td><td class=\"cv\">Sun Mar 15 15:08:07 IST 2020</td><td class=\"cv\"></td><td class=\"cv\">secondHostName0</td></tr>\n" +
                    "</tbody>\n" +
                    "        </table>\n" +
                    "        <hr>\n" +
                    "        <div class=\"bt unrefreshedcerts\">\n" +
                    "            <br>Please review this list and take one of the following actions:\n" +
                    "            <br>\n" +
                    "            <p> 1. Login to the host and verify that sia is able to successfully refresh identity certificates.\n" +
                    "            Address any issues that are reported during the certificate refresh request.</p>\n" +
                    "            <p> 2. After verifying that if the host certificate record is no longer valid due to this\n" +
                    "            instance being re-bootstrapped or changed identity, please delete the\n" +
                    "            certificate record by running the following command (using your domain administrator credentials):</p>\n" +
                    "            <b>curl --key &lt;KEY&gt; --cert &lt;CERT&gt; -X DELETE https://testServer:4443/zts/v1/instance/&lt;PROVIDER&gt;/dom1/&lt;SERVICE&gt;/&lt;INSTANCE-ID&gt; </b>\n" +
                    "            <p>Important: Once the certificate record is deleted, the instance will not be able to\n" +
                    "            refresh its certificates so make sure the record is no longer needed.</p>\n" +
                    "            <p> 3. If you already have monitoring in place for unrefreshed certificates, you may disable unrefreshed\n" +
                    "            certificate notifications by adding the following domain tag:</p>\n" +
                    "            <p>Tag: <b>zts.DisableCertRefreshNotifications</b> Value: <b>true</b></p>\n" +
                    "            <br>For additional support, please review <a href=\"https://athenz.github.io/athenz/\">Athenz Guide</a> or contact us at <a href=\"https://link.to.athenz.channel.com\">#Athenz slack channel</a>\n" +
                    "        </div>\n" +
                    "    </div>\n" +
                    "    <div class=\"footer-container\">\n" +
                    "        <div class=\"footer\">This is a generated email from <a href=\"https://ui-athenz.example.com/\">Athenz</a>. Please do not respond.</div>\n" +
                    "    </div>\n" +
                    "</div>\n" +
                    "</body>\n" +
                    "</html>\n";
    private final String htmlSingleRecord =
            "<div class=\"athenz-wrapper\">\n" +
                    "    <div class=\"mbrapproval unrefreshedcerts\">\n" +
                    "        <div class=\"logo\">\n" +
                    "            <img src=\"cid:logo\" class=\"athenzlogowhite\" alt=\"Athenz logo\"/>\n" +
                    "        </div>\n" +
                    "        <div class=\"hdr\">Unrefreshed Certificates Details</div>\n" +
                    "        <div class=\"bt\">You have one or more certificates that failed to refresh in your Athenz domain <b>dom1</b>:</div>\n" +
                    "        <hr>\n" +
                    "        <table id=\"t02\">\n" +
                    "            <thead>\n" +
                    "                <tr>\n" +
                    "                    <th class=\"ch\">SERVICE</th>\n" +
                    "                    <th class=\"ch\">PROVIDER</th>\n" +
                    "                    <th class=\"ch\">INSTANCE ID</th>\n" +
                    "                    <th class=\"ch\">UPDATE TIME</th>\n" +
                    "                    <th class=\"ch\">EXPIRATION TIME</th>\n" +
                    "                    <th class=\"ch\">HOSTNAME</th>\n" +
                    "                </tr>\n" +
                    "            </thead>\n" +
                    "            <tbody><tr><td class=\"cv\">service1</td><td class=\"cv\">provider1</td><td class=\"cv\">instanceid1</td><td class=\"cv\">Sun Mar 15 15:08:07 IST 2020</td><td class=\"cv\"></td><td class=\"cv\">hostName1</td></tr>\n" +
                    "</tbody>\n" +
                    "        </table>\n" +
                    "        <hr>\n" +
                    "        <div class=\"bt unrefreshedcerts\">\n" +
                    "            <br>Please review this list and take one of the following actions:\n" +
                    "            <br>\n" +
                    "            <p> 1. Login to the host and verify that sia is able to successfully refresh identity certificates.\n" +
                    "            Address any issues that are reported during the certificate refresh request.</p>\n" +
                    "            <p> 2. After verifying that if the host certificate record is no longer valid due to this\n" +
                    "            instance being re-bootstrapped or changed identity, please delete the\n" +
                    "            certificate record by running the following command (using your domain administrator credentials):</p>\n" +
                    "            <b>curl --key &lt;KEY&gt; --cert &lt;CERT&gt; -X DELETE https://testServer:4443/zts/v1/instance/provider1/dom1/service1/instanceid1 </b>\n" +
                    "            <p>Important: Once the certificate record is deleted, the instance will not be able to\n" +
                    "            refresh its certificates so make sure the record is no longer needed.</p>\n" +
                    "            <p> 3. If you already have monitoring in place for unrefreshed certificates, you may disable unrefreshed\n" +
                    "            certificate notifications by adding the following domain tag:</p>\n" +
                    "            <p>Tag: <b>zts.DisableCertRefreshNotifications</b> Value: <b>true</b></p>\n" +
                    "            <br>For additional support, please review <a href=\"https://athenz.github.io/athenz/\">Athenz Guide</a> or contact us at <a href=\"https://link.to.athenz.channel.com\">#Athenz slack channel</a>\n" +
                    "        </div>\n" +
                    "    </div>\n" +
                    "    <div class=\"footer-container\">\n" +
                    "        <div class=\"footer\">This is a generated email from <a href=\"https://ui-athenz.example.com/\">Athenz</a>. Please do not respond.</div>\n" +
                    "    </div>\n" +
                    "</div>\n" +
                    "</body>\n" +
                    "</html>\n";

    @BeforeClass
    public void setup() {
        instanceCertManager = Mockito.mock(InstanceCertManager.class);
        dataStore = Mockito.mock(DataStore.class);
        hostnameResolver = Mockito.mock(HostnameResolver.class);
        notificationToEmailConverterCommon = new NotificationToEmailConverterCommon(null);
    }

    @BeforeMethod
    public void resetDatastore() {
        Mockito.reset(dataStore);
        Mockito.reset(hostnameResolver);
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
                serverName,
                httpsPort,
                notificationToEmailConverterCommon);

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
                serverName,
                httpsPort,
                notificationToEmailConverterCommon);

        List<Notification> notifications = certFailedRefreshNotificationTask.getNotifications();
        assertEquals(6, notifications.size());
        notifications.sort(Comparator.comparing(notif -> notif.getDetails().get(NOTIFICATION_DETAILS_UNREFRESHED_CERTS)));
        // Assert one records for provider1:
        String expectedDetail = "service0;provider1;instanceID0;" + Timestamp.fromMillis(currentDate.getTime()) + ";;hostName0";
        assertEquals(expectedDetail, notifications.get(0).getDetails().get(NOTIFICATION_DETAILS_UNREFRESHED_CERTS));

        // Assert two records for provider2:
        expectedDetail = "service1;provider2;instanceID1;" + Timestamp.fromMillis(currentDate.getTime()) + ";;hostName1";
        assertEquals(expectedDetail, notifications.get(1).getDetails().get(NOTIFICATION_DETAILS_UNREFRESHED_CERTS));

        expectedDetail = "service2;provider2;instanceID2;" + Timestamp.fromMillis(currentDate.getTime()) + ";;hostName2";
        assertEquals(expectedDetail, notifications.get(2).getDetails().get(NOTIFICATION_DETAILS_UNREFRESHED_CERTS));

        // Assert three records for provider3:
        expectedDetail = "service3;provider3;instanceID3;" + Timestamp.fromMillis(currentDate.getTime()) + ";;hostName3";
        assertEquals(expectedDetail, notifications.get(3).getDetails().get(NOTIFICATION_DETAILS_UNREFRESHED_CERTS));

        expectedDetail = "service4;provider3;instanceID4;" + Timestamp.fromMillis(currentDate.getTime()) + ";;hostName4";
        assertEquals(expectedDetail, notifications.get(4).getDetails().get(NOTIFICATION_DETAILS_UNREFRESHED_CERTS));

        expectedDetail = "service5;provider3;instanceID5;" + Timestamp.fromMillis(currentDate.getTime()) + ";;hostName5";
        assertEquals(expectedDetail, notifications.get(5).getDetails().get(NOTIFICATION_DETAILS_UNREFRESHED_CERTS));

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

        // Make a 7th record with no host (but make it valid). It shouldn't return
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
                serverName,
                httpsPort,
                notificationToEmailConverterCommon);

        List<Notification> notifications = certFailedRefreshNotificationTask.getNotifications();
        assertEquals(3, notifications.size());
        assertEquals("domain4", notifications.get(0).getDetails().get("domain"));
        assertEquals("domain2", notifications.get(1).getDetails().get("domain"));
        assertEquals("domain0", notifications.get(2).getDetails().get("domain"));

        System.clearProperty(ZTS_PROP_NOTIFICATION_CERT_FAIL_PROVIDER_LIST);
    }

    @Test
    public void testNoValidHosts() {
        Date currentDate = new Date();
        List<X509CertRecord> records = new ArrayList<>();
        System.setProperty(ZTS_PROP_NOTIFICATION_CERT_FAIL_PROVIDER_LIST, "provider");

        // Create 6 mock records. None of them valid
        boolean isValidHost = true;
        for (int i = 0; i < 6; ++i) {
            X509CertRecord record = getMockX509CertRecord(currentDate, i);
            records.add(record);
            NotificationTestsCommon.mockDomainData(i, dataStore);
            Mockito.when(hostnameResolver.isValidHostname(eq("hostName" + i))).thenReturn(false);
        }

        Mockito.when(instanceCertManager.getUnrefreshedCertsNotifications(eq(serverName), anyString())).thenReturn(records);
        CertFailedRefreshNotificationTask certFailedRefreshNotificationTask = new CertFailedRefreshNotificationTask(
                instanceCertManager,
                dataStore,
                hostnameResolver,
                userDomainPrefix,
                serverName,
                httpsPort,
                notificationToEmailConverterCommon);

        List<Notification> notifications = certFailedRefreshNotificationTask.getNotifications();
        assertEquals(new ArrayList<>(), notifications);

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
        Mockito.when(dataStore.getRolesByDomain(eq(domainName))).thenReturn(new ArrayList<>());
        Mockito.when(hostnameResolver.isValidHostname(eq("hostName1"))).thenReturn(true);

        Mockito.when(instanceCertManager.getUnrefreshedCertsNotifications(eq(serverName), anyString())).thenReturn(records);
        CertFailedRefreshNotificationTask certFailedRefreshNotificationTask = new CertFailedRefreshNotificationTask(
                instanceCertManager,
                dataStore,
                hostnameResolver,
                userDomainPrefix,
                serverName,
                httpsPort,
                notificationToEmailConverterCommon);

        List<Notification> notifications = certFailedRefreshNotificationTask.getNotifications();
        assertEquals(new ArrayList<>(), notifications);

        System.clearProperty(ZTS_PROP_NOTIFICATION_CERT_FAIL_PROVIDER_LIST);
    }

    @Test
    public void testValidServices() {
        String globStrings =
                        "domain0.service0, "
                        + "???????.service1, "
                        + "domain4.????????, ";

        System.setProperty(ZTS_PROP_NOTIFICATION_CERT_FAIL_IGNORED_SERVICES_LIST, globStrings);

        Date currentDate = new Date();
        List<X509CertRecord> records = new ArrayList<>();
        System.setProperty(ZTS_PROP_NOTIFICATION_CERT_FAIL_PROVIDER_LIST, "provider");

        for (int i = 0; i < 6; ++i) {
            X509CertRecord record = getMockX509CertRecord(currentDate, i);
            records.add(record);
            NotificationTestsCommon.mockDomainData(i, dataStore);
            Mockito.when(hostnameResolver.isValidHostname(eq("hostName" + i))).thenReturn(true);
        }

        Mockito.when(instanceCertManager.getUnrefreshedCertsNotifications(eq(serverName), anyString())).thenReturn(records);
        CertFailedRefreshNotificationTask certFailedRefreshNotificationTask = new CertFailedRefreshNotificationTask(
                instanceCertManager,
                dataStore,
                hostnameResolver,
                userDomainPrefix,
                serverName,
                httpsPort,
                notificationToEmailConverterCommon);

        List<Notification> notifications = certFailedRefreshNotificationTask.getNotifications();
        assertEquals(3, notifications.size());
        assertEquals("domain5", notifications.get(0).getDetails().get("domain"));
        assertEquals("domain2", notifications.get(1).getDetails().get("domain"));
        assertEquals("domain3", notifications.get(2).getDetails().get("domain"));

        System.clearProperty(ZTS_PROP_NOTIFICATION_CERT_FAIL_PROVIDER_LIST);
        System.clearProperty(ZTS_PROP_NOTIFICATION_CERT_FAIL_IGNORED_SERVICES_LIST);
    }

    @Test
    public void testNoValidServices() {
        String globStrings = "*";

        System.setProperty(ZTS_PROP_NOTIFICATION_CERT_FAIL_IGNORED_SERVICES_LIST, globStrings);

        Date currentDate = new Date();
        List<X509CertRecord> records = new ArrayList<>();
        System.setProperty(ZTS_PROP_NOTIFICATION_CERT_FAIL_PROVIDER_LIST, "provider");

        for (int i = 0; i < 6; ++i) {
            X509CertRecord record = getMockX509CertRecord(currentDate, i);
            records.add(record);
            NotificationTestsCommon.mockDomainData(i, dataStore);
            Mockito.when(hostnameResolver.isValidHostname(eq("hostName" + i))).thenReturn(true);
        }

        Mockito.when(instanceCertManager.getUnrefreshedCertsNotifications(eq(serverName), anyString())).thenReturn(records);
        CertFailedRefreshNotificationTask certFailedRefreshNotificationTask = new CertFailedRefreshNotificationTask(
                instanceCertManager,
                dataStore,
                hostnameResolver,
                userDomainPrefix,
                serverName,
                httpsPort,
                notificationToEmailConverterCommon);

        List<Notification> notifications = certFailedRefreshNotificationTask.getNotifications();
        assertEquals(new ArrayList<>(), notifications);


        System.clearProperty(ZTS_PROP_NOTIFICATION_CERT_FAIL_PROVIDER_LIST);
        System.clearProperty(ZTS_PROP_NOTIFICATION_CERT_FAIL_IGNORED_SERVICES_LIST);
    }

    @Test
    public void testSomeRecordsSnoozed() {

        Date currentDate = new Date();
        List<X509CertRecord> records = new ArrayList<>();
        System.setProperty(ZTS_PROP_NOTIFICATION_CERT_FAIL_PROVIDER_LIST, "provider");

        DataStore snoozedDataStore = Mockito.mock(DataStore.class);
        for (int i = 0; i < 8; ++i) {
            X509CertRecord record = getMockX509CertRecord(currentDate, i);
            records.add(record);
            NotificationTestsCommon.mockDomainData(i, snoozedDataStore);
            DomainData domainData = new DomainData();
            // Make even domains snooze
            if (i % 2 == 0) {
                Map<String, TagValueList> tags = new HashMap<>();
                tags.put("zts.DisableCertRefreshNotifications", new TagValueList().setList(Arrays.asList("true")));
                domainData.setTags(tags);
            }

            Mockito.when(snoozedDataStore.getDomainData("domain" + i)).thenReturn(domainData);
            Mockito.when(hostnameResolver.isValidHostname(eq("hostName" + i))).thenReturn(true);
        }

        // Have zts.DisableCertRefreshNotifications tag for domain 8 but with value other then "true"
        X509CertRecord record = getMockX509CertRecord(currentDate, 8);
        records.add(record);
        NotificationTestsCommon.mockDomainData(8, snoozedDataStore);
        DomainData domainData = new DomainData();
        Map<String, TagValueList> tags = new HashMap<>();
        tags.put("zts.DisableCertRefreshNotifications", new TagValueList().setList(Arrays.asList("false", "False","Not True")));
        domainData.setTags(tags);
        Mockito.when(snoozedDataStore.getDomainData("domain" + 8)).thenReturn(domainData);
        Mockito.when(hostnameResolver.isValidHostname(eq("hostName" + 8))).thenReturn(true);

        // Have zts.DisableCertRefreshNotifications tag for domain 9 with several values (one of them is true case insensitive)
        record = getMockX509CertRecord(currentDate, 9);
        records.add(record);
        NotificationTestsCommon.mockDomainData(9, snoozedDataStore);
        domainData = new DomainData();
        tags = new HashMap<>();
        tags.put("zts.DisableCertRefreshNotifications", new TagValueList().setList(Arrays.asList("false", "test", "tRue")));
        domainData.setTags(tags);
        Mockito.when(snoozedDataStore.getDomainData("domain" + 9)).thenReturn(domainData);
        Mockito.when(hostnameResolver.isValidHostname(eq("hostName" + 9))).thenReturn(true);

        Mockito.when(instanceCertManager.getUnrefreshedCertsNotifications(eq(serverName), anyString())).thenReturn(records);
        CertFailedRefreshNotificationTask certFailedRefreshNotificationTask = new CertFailedRefreshNotificationTask(
                instanceCertManager,
                snoozedDataStore,
                hostnameResolver,
                userDomainPrefix,
                serverName,
                httpsPort,
                notificationToEmailConverterCommon);

        List<Notification> notifications = certFailedRefreshNotificationTask.getNotifications();
        assertEquals(5, notifications.size());
        assertEquals("domain8", notifications.get(0).getDetails().get("domain"));
        assertEquals("domain7", notifications.get(1).getDetails().get("domain"));
        assertEquals("domain5", notifications.get(2).getDetails().get("domain"));
        assertEquals("domain3", notifications.get(3).getDetails().get("domain"));
        assertEquals("domain1", notifications.get(4).getDetails().get("domain"));

        System.clearProperty(ZTS_PROP_NOTIFICATION_CERT_FAIL_PROVIDER_LIST);
    }

    @Test
    public void testAllRecordsSnoozed() {

        Date currentDate = new Date();
        List<X509CertRecord> records = new ArrayList<>();
        System.setProperty(ZTS_PROP_NOTIFICATION_CERT_FAIL_PROVIDER_LIST, "provider");

        DataStore snoozedDataStore = Mockito.mock(DataStore.class);

        for (int i = 0; i < 8; ++i) {
            X509CertRecord record = getMockX509CertRecord(currentDate, i);
            records.add(record);
            NotificationTestsCommon.mockDomainData(i, snoozedDataStore);
            DomainData domainData = new DomainData();
            // Make all domains snooze
            Map<String, TagValueList> tags = new HashMap<>();
            tags.put("zts.DisableCertRefreshNotifications", new TagValueList().setList(Arrays.asList("true")));
            domainData.setTags(tags);

            Mockito.when(snoozedDataStore.getDomainData("domain" + i)).thenReturn(domainData);
            Mockito.when(hostnameResolver.isValidHostname(eq("hostName" + i))).thenReturn(true);
        }

        Mockito.when(instanceCertManager.getUnrefreshedCertsNotifications(eq(serverName), anyString())).thenReturn(records);
        CertFailedRefreshNotificationTask certFailedRefreshNotificationTask = new CertFailedRefreshNotificationTask(
                instanceCertManager,
                snoozedDataStore,
                hostnameResolver,
                userDomainPrefix,
                serverName,
                httpsPort,
                notificationToEmailConverterCommon);

        List<Notification> notifications = certFailedRefreshNotificationTask.getNotifications();
        assertEquals(new ArrayList<>(), notifications);

        System.clearProperty(ZTS_PROP_NOTIFICATION_CERT_FAIL_PROVIDER_LIST);
    }

    @Test
    public void testValidProvidersNoUnrefreshedCerts() {
        // Configure 3 providers in property
        System.setProperty(ZTS_PROP_NOTIFICATION_CERT_FAIL_PROVIDER_LIST, "provider1, provider2, provider3");
        Mockito.when(instanceCertManager.getUnrefreshedCertsNotifications(eq(serverName), anyString())).thenReturn(new ArrayList<>());
        CertFailedRefreshNotificationTask certFailedRefreshNotificationTask = new CertFailedRefreshNotificationTask(
                instanceCertManager,
                dataStore,
                hostnameResolver,
                userDomainPrefix,
                serverName,
                httpsPort,
                notificationToEmailConverterCommon);
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
                serverName,
                httpsPort,
                notificationToEmailConverterCommon);

        List<Notification> notifications = certFailedRefreshNotificationTask.getNotifications();
        assertEquals(6, notifications.size());
        // Assert 2 records for domain5 and domain0:
        String twoRecordsDomain5 = "service5;provider;instanceID5;" + Timestamp.fromMillis(currentDate.getTime()) + ";;hostName5|" +
                "service5;provider;instanceID5;" + Timestamp.fromMillis(currentDate.getTime()) + ";;secondHostName5";
        assertEquals(twoRecordsDomain5, notifications.get(1).getDetails().get(NOTIFICATION_DETAILS_UNREFRESHED_CERTS));
        String twoRecordsDomain0 = "service0;provider;instanceID0;" + Timestamp.fromMillis(currentDate.getTime()) + ";;hostName0|" +
                "service0;provider;instanceID0;" + Timestamp.fromMillis(currentDate.getTime()) + ";;secondHostName0";
        assertEquals(twoRecordsDomain0, notifications.get(4).getDetails().get(NOTIFICATION_DETAILS_UNREFRESHED_CERTS));

        // Assert other domains only have 1 record:
        String oneRecordDomain1 = "service1;provider;instanceID1;" + Timestamp.fromMillis(currentDate.getTime()) + ";;hostName1";
        assertEquals(oneRecordDomain1, notifications.get(5).getDetails().get(NOTIFICATION_DETAILS_UNREFRESHED_CERTS));

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
                serverName,
                httpsPort,
                notificationToEmailConverterCommon);

        String description = certFailedRefreshNotificationTask.getDescription();
        assertEquals("certificate failed refresh notification", description);
    }

    @Test
    public void testGetEmailBodyMultipleRecords() {
        System.setProperty("athenz.notification_workflow_url", "https://athenz.example.com/workflow");
        System.setProperty("athenz.notification_support_text", "#Athenz slack channel");
        System.setProperty("athenz.notification_support_url", "https://link.to.athenz.channel.com");
        System.setProperty("athenz.notification_athenz_ui_url", "https://ui-athenz.example.com/");


        Map<String, String> details = new HashMap<>();
        details.put("domain", "dom1");
        details.put(NOTIFICATION_DETAILS_UNREFRESHED_CERTS,
                "service0;provider;instanceID0;Sun Mar 15 15:08:07 IST 2020;;hostName0|" +
                        "bad;instanceID0;Sun Mar 15 15:08:07 IST 2020;;hostBad|" + // bad entry with missing provider
                        "service0;provider;instanceID0;Sun Mar 15 15:08:07 IST 2020;;secondHostName0");

        Notification notification = new Notification();
        notification.setDetails(details);
        CertFailedRefreshNotificationTask.CertFailedRefreshNotificationToEmailConverter converter =
                new CertFailedRefreshNotificationTask.CertFailedRefreshNotificationToEmailConverter(serverName, httpsPort, new NotificationToEmailConverterCommon(null));
        NotificationEmail notificationAsEmail = converter.getNotificationAsEmail(notification);

        String body = notificationAsEmail.getBody();
        assertNotNull(body);
        assertTrue(body.contains(htmlSeveralRecords));

        // make sure the bad entries are not included
        assertFalse(body.contains("bad"));
        assertFalse(body.contains("hostBad"));

        System.clearProperty("athenz.notification_workflow_url");
        System.clearProperty("notification_support_text");
        System.clearProperty("notification_support_url");
        System.clearProperty("athenz.notification_athenz_ui_url");
    }

    @Test
    public void testGetEmailBodySingleRecord() {
        System.setProperty("athenz.notification_workflow_url", "https://athenz.example.com/workflow");
        System.setProperty("athenz.notification_support_text", "#Athenz slack channel");
        System.setProperty("athenz.notification_support_url", "https://link.to.athenz.channel.com");
        System.setProperty("athenz.notification_athenz_ui_url", "https://ui-athenz.example.com/");

        Map<String, String> details = new HashMap<>();
        details.put("domain", "dom1");
        details.put(NOTIFICATION_DETAILS_UNREFRESHED_CERTS,
                "service1;provider1;instanceid1;Sun Mar 15 15:08:07 IST 2020;;hostName1");

        Notification notification = new Notification();
        notification.setDetails(details);
        CertFailedRefreshNotificationTask.CertFailedRefreshNotificationToEmailConverter converter = new CertFailedRefreshNotificationTask.CertFailedRefreshNotificationToEmailConverter(serverName, httpsPort, new NotificationToEmailConverterCommon(null));
        NotificationEmail notificationAsEmail = converter.getNotificationAsEmail(notification);

        String body = notificationAsEmail.getBody();
        assertNotNull(body);
        assertTrue(body.contains(htmlSingleRecord));

        System.clearProperty("athenz.notification_workflow_url");
        System.clearProperty("notification_support_text");
        System.clearProperty("notification_support_url");
        System.clearProperty("athenz.notification_athenz_ui_url");
    }

    @Test
    public void getEmailSubject() {
        Notification notification = new Notification();
        CertFailedRefreshNotificationTask.CertFailedRefreshNotificationToEmailConverter converter = new CertFailedRefreshNotificationTask.CertFailedRefreshNotificationToEmailConverter(serverName, httpsPort, notificationToEmailConverterCommon);
        NotificationEmail notificationAsEmail = converter.getNotificationAsEmail(notification);
        String subject = notificationAsEmail.getSubject();
        Assert.assertEquals(subject, "Athenz Unrefreshed Certificates Notification");
    }

    @Test
    public void testGetNotificationAsMetric() {
        Timestamp currentTimeStamp = Timestamp.fromCurrentTime();
        Timestamp fiveDaysAgo = ZTSTestUtils.addDays(currentTimeStamp, -5);
        Timestamp twentyFiveDaysFromNow = ZTSTestUtils.addDays(currentTimeStamp, 25);

        Map<String, String> details = new HashMap<>();
        details.put("domain", "dom1");
        details.put(NOTIFICATION_DETAILS_UNREFRESHED_CERTS,
                        "service0;provider0;instanceID0;" + fiveDaysAgo + ";" + twentyFiveDaysFromNow + ";hostName1|" +
                        "service1;provider1;instanceID1;" + fiveDaysAgo + ";" + twentyFiveDaysFromNow + ";hostName2");

        Notification notification = new Notification();
        notification.setDetails(details);

        CertFailedRefreshNotificationTask.CertFailedRefreshNotificationToMetricConverter converter = new CertFailedRefreshNotificationTask.CertFailedRefreshNotificationToMetricConverter();
        NotificationMetric notificationAsMetrics = converter.getNotificationAsMetrics(notification, currentTimeStamp);

        String[] expectedRecord1 = new String[]{
                METRIC_NOTIFICATION_TYPE_KEY, "cert_fail_refresh",
                METRIC_NOTIFICATION_DOMAIN_KEY, "dom1",
                METRIC_NOTIFICATION_SERVICE_KEY, "service0",
                METRIC_NOTIFICATION_PROVIDER_KEY, "provider0",
                METRIC_NOTIFICATION_INSTANCE_ID_KEY, "instanceID0",
                METRIC_NOTIFICATION_UPDATE_DAYS_KEY, "-5",
                METRIC_NOTIFICATION_EXPIRY_DAYS_KEY, "25"
        };

        String[] expectedRecord2 = new String[]{
                METRIC_NOTIFICATION_TYPE_KEY, "cert_fail_refresh",
                METRIC_NOTIFICATION_DOMAIN_KEY, "dom1",
                METRIC_NOTIFICATION_SERVICE_KEY, "service1",
                METRIC_NOTIFICATION_PROVIDER_KEY, "provider1",
                METRIC_NOTIFICATION_INSTANCE_ID_KEY, "instanceID1",
                METRIC_NOTIFICATION_UPDATE_DAYS_KEY, "-5",
                METRIC_NOTIFICATION_EXPIRY_DAYS_KEY, "25"
        };

        List<String[]> expectedAttributes = new ArrayList<>();
        expectedAttributes.add(expectedRecord1);
        expectedAttributes.add(expectedRecord2);

        assertEquals(new NotificationMetric(expectedAttributes), notificationAsMetrics);
    }
}
