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

package com.yahoo.athenz.syncer.auth.history;

import org.junit.Test;

import java.net.MalformedURLException;

import static org.junit.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.AssertJUnit.fail;

public class LogsParserUtilsTest {

    @Test
    public void testGetRecordFromLogEvent() throws MalformedURLException {

        LogsParserUtils utils = new LogsParserUtils();
        assertNotNull(utils);

        // Test /domain/{domainName}/token
        String message = "98.136.200.210 - user.testprincipal [19/Apr/2022:08:00:45 +0000] \"GET /zms/v1/domain/home.testuser/token HTTP/1.1\" 200 16 \"-\" \"Jersey/2.18 (HttpUrlConnection 1.8.0_302)\" - 2 Auth-X509 TLSv1.2 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        AuthHistoryDynamoDBRecord recordFromLogEvent = LogsParserUtils.getRecordFromLogEvent(message);
        TestUtils.assertRecordMatch(recordFromLogEvent, message);
        assertEquals("GET /zms/v1/domain/home.testuser/token", recordFromLogEvent.getEndpoint());

        // Test /domain/{domainName}/token?role={roleName}
        message = ".211.22.37 - user.testprincipal [19/Apr/2022:08:00:45 +0000] \"GET /zts/v1/domain/home.testuser/token?role=test-role HTTP/1.1\" 200 288 \"-\" \"ZTS-POST-DEPLOY-CHECK\" 0 7 Auth-X509 TLSv1.2 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        recordFromLogEvent = LogsParserUtils.getRecordFromLogEvent(message);
        TestUtils.assertRecordMatch(recordFromLogEvent, message);
        assertEquals("GET /zts/v1/domain/home.testuser/token?role=test-role", recordFromLogEvent.getEndpoint());

        // Test /oauth2/token
        message = "77.238.175.59 - user.testprincipal [19/Apr/2022:08:00:45 +0000] \"POST /zts/v1/oauth2/token?authorization_details=%5B%7B%22type%22%3A%22message_access%22%2C%22uuid%22%3A%221001%22%2C%22mbox-id%22%3A%22mbx-001%22%7D%5D&expires_in=7200&grant_type=client_credentials&scope=home.testuser%3Arole.test-role HTTP/1.1\" 400 69 \"-\" \"Go-http-client/1.1\" 207 2 Auth-X509 TLSv1.2 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        recordFromLogEvent = LogsParserUtils.getRecordFromLogEvent(message);
        TestUtils.assertRecordMatch(recordFromLogEvent, message);
        assertEquals("POST /zts/v1/oauth2/token?authorization_details=%5B%7B%22type%22%3A%22message_access%22%2C%22uuid%22%3A%221001%22%2C%22mbox-id%22%3A%22mbx-001%22%7D%5D&expires_in=7200&grant_type=client_credentials&scope=home.testuser%3Arole.test-role", recordFromLogEvent.getEndpoint());

        // Test /domain/{domainName}/role/{roleName}/token
        message = "77.238.175.59 - user.testprincipal [19/Apr/2022:08:00:45 +0000] \"POST /zts/v1/domain/home.testuser/role/test-role/token HTTP/1.1\" 200 1792 \"-\" \"Go-http-client/1.1\" 1141 158 Auth-X509 TLSv1.2 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        recordFromLogEvent = LogsParserUtils.getRecordFromLogEvent(message);
        TestUtils.assertRecordMatch(recordFromLogEvent, message);
        assertEquals("POST /zts/v1/domain/home.testuser/role/test-role/token", recordFromLogEvent.getEndpoint());

        // Test /access/domain/{domainName}/role/{roleName}/principal/{principal}
        message = "69.147.100.8 - user.testprincipal [19/Apr/2022:08:00:45 +0000] \"GET /zts/v1/access/domain/home.testuser/role/some.role/principal/some.other.principal HTTP/1.1\" 200 380 \"-\" \"Jersey/2.35 (Apache HttpClient 4.5.13)\" - 1 Auth-X509 TLSv1.2 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        recordFromLogEvent = LogsParserUtils.getRecordFromLogEvent(message);
        TestUtils.assertRecordMatch(recordFromLogEvent, message);
        assertEquals("GET /zts/v1/access/domain/home.testuser/role/some.role/principal/some.other.principal", recordFromLogEvent.getEndpoint());

        // Test /access/domain/{domainName}/principal/{principal}
        message = "69.147.100.8 - user.testprincipal [19/Apr/2022:08:00:45 +0000] \"GET /zts/v1/access/domain/home.testuser/principal/some.other.principal HTTP/1.1\" 200 380 \"-\" \"Jersey/2.35 (Apache HttpClient 4.5.13)\" - 1 Auth-X509 TLSv1.2 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        recordFromLogEvent = LogsParserUtils.getRecordFromLogEvent(message);
        TestUtils.assertRecordMatch(recordFromLogEvent, message);
        assertEquals("GET /zts/v1/access/domain/home.testuser/principal/some.other.principal", recordFromLogEvent.getEndpoint());

        // Test /rolecert
        message = "52.6.160.123 - user.testprincipal [19/Apr/2022:08:00:45 +0000] \"POST /zts/v1/rolecert?roleName=home.testuser:role.test-role HTTP/1.1\" 200 2220 \"-\" \"SIA-AWS 2.60.0\" 1549 50 Auth-X509 TLSv1.2 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        recordFromLogEvent = LogsParserUtils.getRecordFromLogEvent(message);
        TestUtils.assertRecordMatch(recordFromLogEvent, message);
        assertEquals("POST /zts/v1/rolecert?roleName=home.testuser:role.test-role", recordFromLogEvent.getEndpoint());

        // Test /access/{action}/{resource}
        message = "98.136.200.210 - user.testprincipal [19/Apr/2022:08:00:45 +0000] \"GET /zms/v1/access/create/home.testuser:testsource?principal=some.principal HTTP/1.1\" 200 16 \"-\" \"Jersey/2.18 (HttpUrlConnection 1.8.0_302)\" - 2 Auth-X509 TLSv1.2 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        recordFromLogEvent = LogsParserUtils.getRecordFromLogEvent(message);
        TestUtils.assertRecordMatch(recordFromLogEvent, message);
        assertEquals("GET /zms/v1/access/create/home.testuser:testsource?principal=some.principal", recordFromLogEvent.getEndpoint());

        // Test /access/{action}/{resource}?domain={trustDomain}
        message = "98.136.200.210 - user.testprincipal [19/Apr/2022:08:00:45 +0000] \"GET /zms/v1/access/create/home.origdomain:testsource?principal=some.principal&domain=home.testuser HTTP/1.1\" 200 16 \"-\" \"Jersey/2.18 (HttpUrlConnection 1.8.0_302)\" - 2 Auth-X509 TLSv1.2 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        recordFromLogEvent = LogsParserUtils.getRecordFromLogEvent(message);
        TestUtils.assertRecordMatch(recordFromLogEvent, message);
        assertEquals("GET /zms/v1/access/create/home.origdomain:testsource?principal=some.principal&domain=home.testuser", recordFromLogEvent.getEndpoint());

        // Test /access/{action}?resource={resource}&domain={trustDomain}
        message = "98.136.200.210 - user.testprincipal [19/Apr/2022:08:00:45 +0000] \"GET /zms/v1/access/create?principal=some.principal&domain=home.testuser&resource=home.origdomain:testsource HTTP/1.1\" 200 16 \"-\" \"Jersey/2.18 (HttpUrlConnection 1.8.0_302)\" - 2 Auth-X509 TLSv1.2 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        recordFromLogEvent = LogsParserUtils.getRecordFromLogEvent(message);
        TestUtils.assertRecordMatch(recordFromLogEvent, message);
        assertEquals("GET /zms/v1/access/create?principal=some.principal&domain=home.testuser&resource=home.origdomain:testsource", recordFromLogEvent.getEndpoint());

        message="87.248.108.86 - user.testprincipal [19/Apr/2022:08:00:45 +0000] \"GET /zms/v1/access/sudo_test?resource=home.testuser:testsource&principal=user.testprincipal HTTP/1.1\" 200 16 \"-\" \"Go-http-client/1.1\" 0 22 Auth-X509 TLSv1.2 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        recordFromLogEvent = LogsParserUtils.getRecordFromLogEvent(message);
        TestUtils.assertRecordMatch(recordFromLogEvent, message);
        assertEquals("GET /zms/v1/access/sudo_test?resource=home.testuser:testsource&principal=user.testprincipal", recordFromLogEvent.getEndpoint());
    }

    @Test
    public void testGetRecordFromLogEventException() {
        String message = "98.136.200.210 - user.testprincipal [19/Apr/2022:08:00:45 +0000] \"GET /zms/v1/access/create?principal=some.principal HTTP/1.1\" 200 16 \"-\" \"Jersey/2.18 (HttpUrlConnection 1.8.0_302)\" - 2 Auth-X509 TLSv1.2 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        try {
            LogsParserUtils.getRecordFromLogEvent(message);
            fail();
        } catch (MalformedURLException e) {
            assertEquals("Failed to locate domain at endpoint: /zms/v1/access/create?principal=some.principal", e.getMessage());
        }
    }
}