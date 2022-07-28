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

package com.yahoo.athenz.syncer.auth.history.impl;


import com.yahoo.athenz.syncer.auth.history.AuthHistoryDynamoDBRecord;
import org.testng.annotations.Test;

import java.text.ParseException;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.testng.AssertJUnit.*;

public class LocalAuthHistoryFetcherTest {

    @Test
    public void testGetFileNameFromTimestamp() {
        System.setProperty(LocalAuthHistoryFetcher.ATHENZ_PROP_ACCESS_LOG_DIR, "/home/athenz/logs");
        LocalAuthHistoryFetcher localAuthHistoryFetcher = new LocalAuthHistoryFetcher();
        Long time = 1654803078111L;
        String fileNameFromTimestamp = localAuthHistoryFetcher.getFileNameFromTimestamp(time);
        assertEquals(fileNameFromTimestamp, "/home/athenz/logs/access.2022_06_09.log");
        System.clearProperty(LocalAuthHistoryFetcher.ATHENZ_PROP_ACCESS_LOG_DIR);
    }

    @Test
    public void testIsAuthRecordInTimeRange() throws ParseException {
        System.setProperty(LocalAuthHistoryFetcher.ATHENZ_PROP_ACCESS_LOG_DIR, "/home/athenz/logs");
        LocalAuthHistoryFetcher localAuthHistoryFetcher = new LocalAuthHistoryFetcher();

        String timeInLog = "19/Apr/2022:08:00:45";
        long startTime = 1650271929000L; // 18/Apr/2022:08:52:09
        long endTime = 1650444729000L; // 20/Apr/2022:08:52:09
        String message1 = "77.238.175.59 - user.testprincipal1 [" + timeInLog + " +0000] \"POST /zts/v1/oauth2/token?authorization_details=%5B%7B%22type%22%3A%22message_access%22%2C%22uuid%22%3A%221001%22%2C%22mbox-id%22%3A%22mbx-001%22%7D%5D&expires_in=7200&grant_type=client_credentials&scope=home.testuser%3Arole.test-role HTTP/1.1\" 400 69 \"-\" \"Go-http-client/1.1\" 207 2 Auth-X509 TLSv1.2 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        assertTrue(localAuthHistoryFetcher.isAuthRecordInTimeRangeAndValid(message1, startTime, endTime));

        startTime = 1650444729000L; // 20/Apr/2022:08:52:09
        endTime = 1650531129000L; // 21/Apr/2022:08:52:09
        assertFalse(localAuthHistoryFetcher.isAuthRecordInTimeRangeAndValid(message1, startTime, endTime));

        startTime = 1650185529000L; // 17/Apr/2022:08:52:09
        endTime = 1650271929000L; // 18/Apr/2022:08:52:09
        assertFalse(localAuthHistoryFetcher.isAuthRecordInTimeRangeAndValid(message1, startTime, endTime));

        startTime = 1650355244000L; // 19/Apr/2022:08:00:44
        endTime = 1650355246000L; // 19/Apr/2022:08:00:46
        assertTrue(localAuthHistoryFetcher.isAuthRecordInTimeRangeAndValid(message1, startTime, endTime));
        System.clearProperty(LocalAuthHistoryFetcher.ATHENZ_PROP_ACCESS_LOG_DIR);
    }

    @Test
    public void testGetLogs() {
        System.setProperty(LocalAuthHistoryFetcher.ATHENZ_PROP_ACCESS_LOG_DIR, "src/test/resources/impl");
        LocalAuthHistoryFetcher localAuthHistoryFetcher = new LocalAuthHistoryFetcher();
        Long startTime = 1654819140000L; // 09/Jun/2022:23:59:00
        Long endTime = 1654819201000L; // 10/Jun/2022:00:00:01
        Set<AuthHistoryDynamoDBRecord> logs = localAuthHistoryFetcher.getLogs(startTime, endTime, true);
        List<String> justPrincipals = logs.stream().map(record -> record.getPrimaryKey()).collect(Collectors.toList());
        assertEquals(7, justPrincipals.size());
        assertTrue(justPrincipals.contains("home.testuser:user:testprincipal4"));
        assertTrue(justPrincipals.contains("home.testuser:user:testprincipal5"));
        assertTrue(justPrincipals.contains("home.testuser2:user:testprincipal1"));
        assertTrue(justPrincipals.contains("home.testuser3:user:testprincipal1"));
        assertTrue(justPrincipals.contains("home.testuser:user:testprincipal1"));
        assertTrue(justPrincipals.contains("home.testuser:user:testprincipal2"));
        assertTrue(justPrincipals.contains("home.testuser:user:testprincipal3"));
        System.clearProperty(LocalAuthHistoryFetcher.ATHENZ_PROP_ACCESS_LOG_DIR);
    }
}
