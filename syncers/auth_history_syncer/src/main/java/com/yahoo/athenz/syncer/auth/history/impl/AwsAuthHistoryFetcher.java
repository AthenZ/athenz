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
import com.yahoo.athenz.syncer.auth.history.AuthHistoryFetcher;
import com.yahoo.athenz.syncer.auth.history.CloudWatchClientFactory;
import com.yahoo.athenz.syncer.auth.history.LogsParserUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.services.cloudwatch.model.CloudWatchException;
import software.amazon.awssdk.services.cloudwatchlogs.CloudWatchLogsClient;
import software.amazon.awssdk.services.cloudwatchlogs.model.FilterLogEventsRequest;
import software.amazon.awssdk.services.cloudwatchlogs.model.FilterLogEventsResponse;
import software.amazon.awssdk.services.cloudwatchlogs.model.FilteredLogEvent;

import java.net.MalformedURLException;
import java.util.HashSet;
import java.util.Set;

public class AwsAuthHistoryFetcher implements AuthHistoryFetcher {
    private static final Logger LOGGER = LoggerFactory.getLogger(AwsAuthHistoryFetcher.class);
    private final CloudWatchLogsClient cloudWatchLogsClient;

    public AwsAuthHistoryFetcher(CloudWatchClientFactory cloudWatchClientFactory) {
        this.cloudWatchLogsClient = cloudWatchClientFactory.create();
    }

    /**
     *
     * @param startTime - the start of the time range, expressed as the number of milliseconds after Jan 1, 1970 00:00:00 UTC (for example, 1620940080)
     * @param endTime - the end of the time range, expressed as the number of milliseconds after Jan 1, 1970 00:00:00 UTC (for example, 1620940080)
     * @return - authorization checks and token requests history ready to be pushed to a data store. On error return null.
     */
    @Override
    public Set<AuthHistoryDynamoDBRecord> getLogs(Long startTime, Long endTime) {
        Set<AuthHistoryDynamoDBRecord> zmsLogs = getLogs("athenz-zms-service-access", startTime, endTime);
        Set<AuthHistoryDynamoDBRecord> ztsLogs = getLogs("athenz-zts-service-access", startTime, endTime);
        Set<AuthHistoryDynamoDBRecord> allRecords = new HashSet<>();
        if (zmsLogs != null && !zmsLogs.isEmpty()) {
            allRecords.addAll(zmsLogs);
        }
        if (ztsLogs != null && !ztsLogs.isEmpty()) {
            allRecords.addAll(ztsLogs);
        }
        return allRecords;
    }

    /**
     *
     * @param logGroup - Log group name
     * @param startTime - the start of the time range, expressed as the number of milliseconds after Jan 1, 1970 00:00:00 UTC (for example, 1620940080)
     * @param endTime - the end of the time range, expressed as the number of milliseconds after Jan 1, 1970 00:00:00 UTC (for example, 1620940080)
     * @return - authorization checks and token requests history ready to be pushed to a data store. On error return null.
     */
    private Set<AuthHistoryDynamoDBRecord> getLogs(String logGroup, Long startTime, Long endTime) {
        LOGGER.info("Getting logs from logGroup " + logGroup + ", startTime(milli): " + startTime + ", endTime(milli): " + endTime);
        try {
            String nextToken = null;
            Set<AuthHistoryDynamoDBRecord> filteredEvents = new HashSet<>();
            do {
                FilterLogEventsRequest filterLogEventsRequest = FilterLogEventsRequest.builder()
                        .logGroupName(logGroup)
                        .startTime(startTime)
                        .endTime(endTime)
                        .nextToken(nextToken)
                        .filterPattern("?\"/access/\" ?\"/token\" ?\"/rolecert\"")
                        .build();
                FilterLogEventsResponse filterLogEventsResponse = cloudWatchLogsClient.filterLogEvents(filterLogEventsRequest);
                nextToken = filterLogEventsResponse.nextToken();
                for (FilteredLogEvent filteredLogEvent : filterLogEventsResponse.events()) {
                    try {
                        AuthHistoryDynamoDBRecord record = LogsParserUtils.getRecordFromLogEvent(filteredLogEvent.message());
                        filteredEvents.add(record); // Only keep a single record per key (domain + principal pair)
                    } catch (MalformedURLException e) {
                        LOGGER.error("Failed to parse log event: {}", filteredLogEvent.message(), e);
                    }
                }
            } while (nextToken != null && !nextToken.isEmpty());
            return filteredEvents;
        } catch (CloudWatchException e) {
            LOGGER.error("Failed to parse log event: " + e.awsErrorDetails().errorMessage());
            return null;
        }
    }
}
