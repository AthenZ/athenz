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
import com.yahoo.athenz.zms.DomainData;
import com.yahoo.athenz.zts.cert.InstanceCertManager;
import com.yahoo.athenz.zts.store.DataStore;
import org.mockito.Mockito;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.sql.Timestamp;
import java.util.*;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
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
    public void testValidHosts() {
        Date currentDate = new Date();
        List<X509CertRecord> records = new ArrayList<>();

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

        Mockito.when(instanceCertManager.getUnrefreshedCertsNotifications(eq(serverName))).thenReturn(records);
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
    }

    @Test
    public void testNoValidRecipient() {
        Date currentDate = new Date();
        List<X509CertRecord> records = new ArrayList<>();

        X509CertRecord record = getMockX509CertRecord(currentDate, 1);
        records.add(record);

        String domainName = "domain1";
        Mockito.when(dataStore.getDomainData(eq(domainName))).thenReturn(new DomainData());
        Mockito.when(hostnameResolver.isValidHostname(eq("hostName1"))).thenReturn(true);

        Mockito.when(instanceCertManager.getUnrefreshedCertsNotifications(eq(serverName))).thenReturn(records);
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
    public void testNoUnrefreshedCerts() {
        Mockito.when(instanceCertManager.getUnrefreshedCertsNotifications(eq(serverName))).thenReturn(new ArrayList<>());
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

        Mockito.when(instanceCertManager.getUnrefreshedCertsNotifications(eq(serverName))).thenReturn(records);
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
}
