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

import com.yahoo.athenz.syncer.auth.history.impl.AwsAuthHistoryFetcher;
import org.junit.Test;
import org.mockito.Mockito;
import software.amazon.awssdk.services.cloudwatchlogs.CloudWatchLogsClient;
import software.amazon.awssdk.services.cloudwatchlogs.model.FilterLogEventsRequest;
import software.amazon.awssdk.services.cloudwatchlogs.model.FilterLogEventsResponse;
import software.amazon.awssdk.services.cloudwatchlogs.model.FilteredLogEvent;

import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertTrue;

public class AwsAuthHistoryFetcherTest {

    @Test
    public void testGetLogs() throws MalformedURLException {
        CloudWatchClientFactory cloudWatchClientFactory = Mockito.mock(CloudWatchClientFactory.class);
        CloudWatchLogsClient cloudWatchLogsClient = Mockito.mock(CloudWatchLogsClient.class);
        Long endTime = System.currentTimeMillis();
        Long startTime = endTime - (TimeUnit.MINUTES.toMillis(15));
        String nextToken = null;

        // /oauth2/token
        String principal1 = "user.testprincipal1";
        String domain1 = "home.testuser";
        String message1 = "77.238.175.59 - " + principal1 + " [19/Apr/2022:08:00:45 +0000] \"POST /zts/v1/oauth2/token?authorization_details=%5B%7B%22type%22%3A%22message_access%22%2C%22uuid%22%3A%221001%22%2C%22mbox-id%22%3A%22mbx-001%22%7D%5D&expires_in=7200&grant_type=client_credentials&scope=" + domain1 + "%3Arole.test-role HTTP/1.1\" 400 69 \"-\" \"Go-http-client/1.1\" 207 2 Auth-X509 TLSv1.2 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        FilteredLogEvent filteredLogEvent1 = FilteredLogEvent
                .builder()
                .message(message1)
                .build();

        // /access/domain/{domainName}/role/{roleName}/principal/{principal}
        String principal2 = "user.testprincipal2";
        String domain2 = "home.testuser";
        String message2 = "69.147.100.8 - " + principal2 + " [19/Apr/2022:08:00:45 +0000] \"GET /zts/v1/access/domain/" + domain2 + "/role/some.role/principal/some.other.principal HTTP/1.1\" 200 380 \"-\" \"Jersey/2.35 (Apache HttpClient 4.5.13)\" - 1 Auth-X509 TLSv1.2 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        FilteredLogEvent filteredLogEvent2 = FilteredLogEvent
                .builder()
                .message(message2)
                .build();

        // /access/{action}/{resource}?domain={trustDomain}
        // *Only one record per principal and domain.
        // In this case we'll use the same domain and principal as the previous record - the previous one will be removed and this one will be inserted instead.
        String message3 = "98.136.200.210 - " + principal2 + " [19/Apr/2022:08:00:45 +0000] \"GET /zms/v1/access/create/home.origdomain:testsource?principal=some.principal&domain=" + domain2 + " HTTP/1.1\" 200 16 \"-\" \"Jersey/2.18 (HttpUrlConnection 1.8.0_302)\" - 2 Auth-X509 TLSv1.2 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        FilteredLogEvent filteredLogEvent3 = FilteredLogEvent
                .builder()
                .message(message3)
                .build();

        // /access/{action}/{resource}?domain={trustDomain}
        // In this case we'll use the same principal but a different domain so it will be considered a separate record
        String domain4 = "home.testuser4";
        String message4 = "98.136.200.210 - " + principal2 + " [19/Apr/2022:08:00:45 +0000] \"GET /zms/v1/access/create/home.origdomain:testsource?principal=some.principal&domain=" + domain4 + " HTTP/1.1\" 200 16 \"-\" \"Jersey/2.18 (HttpUrlConnection 1.8.0_302)\" - 2 Auth-X509 TLSv1.2 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        FilteredLogEvent filteredLogEvent4 = FilteredLogEvent
                .builder()
                .message(message4)
                .build();

        // /rolecert?roleName={domain}:role.{role}
        String domain5 = "home.testuser5";
        String message5 = "98.136.200.210 - " + principal2 + " [19/Apr/2022:08:00:45 +0000] \"POST /zts/v1/rolecert?roleName=" + domain5 + ":role.test-role" + " HTTP/1.1\" 200 16 \"-\" \"Jersey/2.18 (HttpUrlConnection 1.8.0_302)\" - 2 Auth-X509 TLSv1.2 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        FilteredLogEvent filteredLogEvent5 = FilteredLogEvent
                .builder()
                .message(message5)
                .build();

        List<FilteredLogEvent> filteredLogEvents = new ArrayList<>();
        filteredLogEvents.add(filteredLogEvent1);
        filteredLogEvents.add(filteredLogEvent2);
        filteredLogEvents.add(filteredLogEvent3);
        filteredLogEvents.add(filteredLogEvent4);
        filteredLogEvents.add(filteredLogEvent5);
        FilterLogEventsResponse ztsResponse = FilterLogEventsResponse.builder()
                .nextToken(null)
                .events(filteredLogEvents)
                .build();
        FilterLogEventsRequest ztsRequest = FilterLogEventsRequest.builder()
                .logGroupName("athenz-zts-service-access")
                .startTime(startTime)
                .endTime(endTime)
                .nextToken(nextToken)
                .filterPattern("?\"/access/\" ?\"/token\" ?\"/rolecert\"")
                .build();
        Mockito.when(cloudWatchLogsClient.filterLogEvents(Mockito.eq(ztsRequest))).thenReturn(ztsResponse);
        FilterLogEventsResponse zmsResponse = FilterLogEventsResponse.builder()
                .nextToken(null)
                .build();
        FilterLogEventsRequest zmsRequest = FilterLogEventsRequest.builder()
                .logGroupName("athenz-zms-service-access")
                .startTime(startTime)
                .endTime(endTime)
                .nextToken(nextToken)
                .filterPattern("?\"/access/\" ?\"/token\" ?\"/rolecert\"")
                .build();
        Mockito.when(cloudWatchLogsClient.filterLogEvents(Mockito.eq(zmsRequest))).thenReturn(zmsResponse);
        Mockito.when(cloudWatchClientFactory.create()).thenReturn(cloudWatchLogsClient);
        AwsAuthHistoryFetcher awsAuthHistoryFetcher = new AwsAuthHistoryFetcher(cloudWatchClientFactory);

        // Mocks ready, get the logs
        Set<AuthHistoryDynamoDBRecord> logRecords = awsAuthHistoryFetcher.getLogs(startTime, endTime, true);

        // Assert we get the expected four records
        assertEquals(4, logRecords.size());
        assertTrue(logRecords.contains(LogsParserUtils.getRecordFromLogEvent(message1)));
        assertTrue(logRecords.contains(LogsParserUtils.getRecordFromLogEvent(message3)));
        assertTrue(logRecords.contains(LogsParserUtils.getRecordFromLogEvent(message4)));
        assertTrue(logRecords.contains(LogsParserUtils.getRecordFromLogEvent(message5)));
    }
}
