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

package com.yahoo.athenz.zms.store.impl.dynamodb;

import com.yahoo.athenz.zms.AuthHistory;
import com.yahoo.athenz.zms.ResourceException;
import com.yahoo.athenz.zms.store.AuthHistoryStoreConnection;
import com.yahoo.athenz.zms.utils.ZMSUtils;
import com.yahoo.rdl.Timestamp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;
import software.amazon.awssdk.services.dynamodb.model.ResourceNotFoundException;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import java.util.stream.Collectors;

public class DynamoDBAuthHistoryStoreConnection implements AuthHistoryStoreConnection {
    private final DynamoDbTable<AuthHistoryDynamoDBRecord> table;
    private static final Logger LOGGER = LoggerFactory.getLogger(DynamoDBAuthHistoryStoreConnection.class);

    public DynamoDBAuthHistoryStoreConnection(final DynamoDbTable<AuthHistoryDynamoDBRecord> table) {
        this.table = table;
    }

    @Override
    public void close() {

    }

    @Override
    public void setOperationTimeout(int opTimeout) {

    }

    @Override
    public List<AuthHistory> getAuthHistory(String domain) {
        try {
            // Create a QueryConditional object that is used in the query operation.
            QueryConditional queryConditional = QueryConditional
                    .keyEqualTo(Key.builder().partitionValue(domain)
                            .build());
            return table.query(r -> r.queryConditional(queryConditional))
                    .items()
                    .stream()
                    .map(record -> {
                        AuthHistory authHistory = new AuthHistory();
                        authHistory.setDomainName(record.getDomain());
                        authHistory.setPrincipal(record.getPrincipal());
                        authHistory.setEndpoint(record.getEndpoint());
                        authHistory.setTimestamp(getAuthHistoryTimeStamp(record));
                        authHistory.setTtl(record.getTtl());
                        return authHistory;
                    })
                    .collect(Collectors.toList());
        } catch (ResourceNotFoundException resourceNotFoundException) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, resourceNotFoundException.getMessage(), "getAuthHistory");
        }
    }

    Timestamp getAuthHistoryTimeStamp(AuthHistoryDynamoDBRecord authHistoryDynamoDBRecord) {
        try {
            SimpleDateFormat formatter = new SimpleDateFormat("dd/MMM/yyyy:HH:mm:ss", Locale.ENGLISH);
            formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
            Date date = formatter.parse(authHistoryDynamoDBRecord.getTimestamp());
            Timestamp timestamp = Timestamp.fromDate(date);
            return timestamp;
        } catch (ParseException e) {
            LOGGER.error("Error parsing timestamp for authHistoryDynamoDBRecord, timestamp will be empty: {}", authHistoryDynamoDBRecord);
            return null;
        }
    }
}
