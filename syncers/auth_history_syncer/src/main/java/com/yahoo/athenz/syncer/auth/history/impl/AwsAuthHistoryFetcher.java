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

import com.yahoo.athenz.syncer.auth.history.*;
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

    private final String zmsLogGroup = System.getProperty(AuthHistorySyncerConsts.PROP_CLOUDWATCH_ZMS_LOG_GROUP,
            "athenz-zms-service-access");
    private final String ztsLogGroup = System.getProperty(AuthHistorySyncerConsts.PROP_CLOUDWATCH_ZTS_LOG_GROUP,
            "athenz-zts-service-access");

    public AwsAuthHistoryFetcher(CloudWatchClientFactory cloudWatchClientFactory) {
        this.cloudWatchLogsClient = cloudWatchClientFactory.create();
    }

    /**
     *
     * @param startTime - the start of the time range, expressed as the number of milliseconds
     *       after Jan 1, 1970 00:00:00 UTC (for example, 1620940080)
     * @param endTime - the end of the time range, expressed as the number of milliseconds
     *      after Jan 1, 1970 00:00:00 UTC (for example, 1620940080)
     * @param useFilterPattern - if true, filter access events in request. False means that
     *      all events in the time range will return.
     * @return - authorization checks and token requests history ready to be pushed to a
     *      data store. On error return null.
     */
    @Override
    public Set<AuthHistoryDynamoDBRecord> getLogs(Long startTime, Long endTime, boolean useFilterPattern) {
        Set<AuthHistoryDynamoDBRecord> zmsLogs = getLogs(zmsLogGroup, startTime, endTime, useFilterPattern);
        Set<AuthHistoryDynamoDBRecord> ztsLogs = getLogs(ztsLogGroup, startTime, endTime, useFilterPattern);
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
     * @param startTime - the start of the time range, expressed as the number of milliseconds
     *       after Jan 1, 1970 00:00:00 UTC (for example, 1620940080)
     * @param endTime - the end of the time range, expressed as the number of milliseconds
     *       after Jan 1, 1970 00:00:00 UTC (for example, 1620940080)
     * @param useFilterPattern - if true, filter access events in request. False means that
     *       all events in the time range will return.
     * @return - authorization checks and token requests history ready to be pushed to a
     *       data store. On error return null.
     */
    private Set<AuthHistoryDynamoDBRecord> getLogs(String logGroup, Long startTime, Long endTime, boolean useFilterPattern) {

        LOGGER.info("Getting logs from logGroup {}, startTime(milli): {}, endTime(milli): {}, useFilterPattern: {}",
                logGroup, startTime, endTime, useFilterPattern);

        try {
            String nextToken = null;
            Set<AuthHistoryDynamoDBRecord> filteredEvents = new HashSet<>();
            do {
                FilterLogEventsRequest.Builder builder = FilterLogEventsRequest.builder()
                        .logGroupName(logGroup)
                        .startTime(startTime)
                        .endTime(endTime)
                        .nextToken(nextToken);
                FilterLogEventsRequest filterLogEventsRequest = useFilterPattern ?
                        builder.filterPattern("?\"/access/\" ?\"/token\" ?\"/rolecert\"").build() :
                        builder.build();
                FilterLogEventsResponse filterLogEventsResponse = cloudWatchLogsClient.filterLogEvents(filterLogEventsRequest);
                nextToken = filterLogEventsResponse.nextToken();
                for (FilteredLogEvent filteredLogEvent : filterLogEventsResponse.events()) {
                    String message = filteredLogEvent.message();
                    try {
                        if (LOGGER.isDebugEnabled()) {
                            LOGGER.debug(message);
                        }
                        AuthHistoryDynamoDBRecord record = LogsParserUtils.getRecordFromLogEvent(message);
                        filteredEvents.add(record); // Only keep a single record per key (domain + principal pair)
                    } catch (MalformedURLException e) {
                        LOGGER.error("Failed to parse log event: {}", message, e);
                    }
                }
            } while (nextToken != null && !nextToken.isEmpty());
            return filteredEvents;
        } catch (CloudWatchException e) {
            LOGGER.error("Failed to parse log event: {}", e.awsErrorDetails().errorMessage(), e);
            return null;
        }
    }
}
