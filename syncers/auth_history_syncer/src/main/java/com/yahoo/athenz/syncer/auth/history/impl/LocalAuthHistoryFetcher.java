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
import com.yahoo.athenz.syncer.auth.history.LogsParserUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.FileReader;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

public class LocalAuthHistoryFetcher implements AuthHistoryFetcher {
    private static final Logger LOGGER = LoggerFactory.getLogger(LocalAuthHistoryFetcher.class);

    public static final String ATHENZ_PROP_ACCESS_LOG_DIR = "athenz.access_log_dir";
    public static final String ATHENZ_PROP_ROOT_DIR = "athenz.root_dir";
    public static final String STR_DEF_ROOT = "/home/athenz";
    private final String logDir;

    public LocalAuthHistoryFetcher() {
        String rootDir = System.getProperty(ATHENZ_PROP_ROOT_DIR, STR_DEF_ROOT);
        logDir = System.getProperty(ATHENZ_PROP_ACCESS_LOG_DIR,
                rootDir + "/logs/athenz");
    }

    @Override
    public Set<AuthHistoryDynamoDBRecord> getLogs(Long startTime, Long endTime, boolean useFilterPattern) {
        // The log files are expected to be in the format access.yyyy_MM_dd.log
        String logFileNameStart = getFileNameFromTimestamp(startTime);
        String logFileNameEnd = getFileNameFromTimestamp(endTime);
        Set<AuthHistoryDynamoDBRecord> records = getRecordsFromFile(logFileNameStart, startTime, endTime);
        if (!logFileNameEnd.equals(logFileNameStart)) {
            records.addAll(getRecordsFromFile(logFileNameEnd, startTime, endTime));
        }
        return records;
    }

    private Set<AuthHistoryDynamoDBRecord> getRecordsFromFile(String logFileName, Long startTime, Long endTime) {
        Set<AuthHistoryDynamoDBRecord> records = new HashSet<>();
        try (BufferedReader stdin = new BufferedReader(new FileReader(logFileName))) {
            String line;
            while ((line = stdin.readLine()) != null) {
                try {
                    if (isAuthRecordInTimeRangeAndValid(line, startTime, endTime)) {
                        records.add(LogsParserUtils.getRecordFromLogEvent(line));
                    }
                } catch (Exception e) {
                    LOGGER.error("Failed to parse log event. line={}", line, e);
                }
            }
        } catch (Exception e) {
            LOGGER.error("Failed to parse log event", e);
            return null;
        }

        return records;
    }

    boolean isAuthRecordInTimeRangeAndValid(String logLine, long startTime, long endTime) throws ParseException {
        //filterPattern("?\"/access/\" ?\"/token\" ?\"/rolecert\"")
        if (logLine.contains("/access") || logLine.contains("/token") || logLine.contains("/rolecert")) {
            String[] split = logLine.split("\\s+");
            long timestamp = getUnixEpocFromTimestamp(split[3].substring(1));
            return timestamp >= startTime && timestamp <= endTime;
        }
        return false;
    }

    String getFileNameFromTimestamp(long timestamp) {
        SimpleDateFormat formatter = new SimpleDateFormat("yyyy_MM_dd", Locale.ENGLISH);
        formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
        Date date = new Date(timestamp);
        String dateFileName = formatter.format(date);
        return logDir + "/access." + dateFileName + ".log";
    }

    Long getUnixEpocFromTimestamp(String timestamp) throws ParseException {
        SimpleDateFormat formatter = new SimpleDateFormat("dd/MMM/yyyy:HH:mm:ss", Locale.ENGLISH);
        formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
        Date date = formatter.parse(timestamp);
        return date.getTime();
    }
}
