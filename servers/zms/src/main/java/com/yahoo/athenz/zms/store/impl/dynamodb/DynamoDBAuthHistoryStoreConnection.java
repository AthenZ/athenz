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
import com.yahoo.athenz.zms.AuthHistoryDependencies;
import com.yahoo.athenz.zms.ResourceException;
import com.yahoo.athenz.zms.ZMSConsts;
import com.yahoo.athenz.zms.store.AuthHistoryStoreConnection;
import com.yahoo.athenz.zms.utils.ZMSUtils;
import com.yahoo.rdl.Timestamp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbIndex;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.model.Page;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;
import software.amazon.awssdk.services.dynamodb.model.ResourceNotFoundException;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import java.util.stream.Collectors;

/**
 * DynamoDBAuthHistoryStoreConnection expects that a DynamoDB table exists according to the properties in {@link AuthHistoryDynamoDBRecord}
 */
public class DynamoDBAuthHistoryStoreConnection implements AuthHistoryStoreConnection {
    private static final Logger LOGGER = LoggerFactory.getLogger(DynamoDBAuthHistoryStoreConnection.class);
    private final DynamoDbIndex<AuthHistoryDynamoDBRecord> principalDomainIndex;
    private final DynamoDbIndex<AuthHistoryDynamoDBRecord> uriDomainIndex;

    public DynamoDBAuthHistoryStoreConnection(final DynamoDbTable<AuthHistoryDynamoDBRecord> table) {
        this.principalDomainIndex = table.index(ZMSConsts.ZMS_DYNAMODB_PRINCIPAL_DOMAIN_INDEX_NAME);
        this.uriDomainIndex = table.index(ZMSConsts.ZMS_DYNAMODB_URI_DOMAIN_INDEX_NAME);
    }

    @Override
    public void close() {

    }

    @Override
    public void setOperationTimeout(int opTimeout) {

    }

    @Override
    public AuthHistoryDependencies getAuthHistory(String domain) {
        try {
            List<AuthHistory> principalDomainList = getRecordsFromDomainIndex(principalDomainIndex, domain);
            List<AuthHistory> uriDomainList = getRecordsFromDomainIndex(uriDomainIndex, domain);
            AuthHistoryDependencies authHistoryDependencies = new AuthHistoryDependencies();
            authHistoryDependencies.setOutgoingDependencies(principalDomainList);
            authHistoryDependencies.setIncomingDependencies(uriDomainList);
            return authHistoryDependencies;
        } catch (ResourceNotFoundException resourceNotFoundException) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, resourceNotFoundException.getMessage(), "getAuthHistory");
        }
    }

    private List<AuthHistory> getRecordsFromDomainIndex(DynamoDbIndex<AuthHistoryDynamoDBRecord> domainIndex, String domain) {
        QueryConditional queryConditional = QueryConditional
                .keyEqualTo(Key.builder().partitionValue(domain)
                        .build());

        return domainIndex.query(r -> r.queryConditional(queryConditional))
                .stream()
                .map(Page::items)
                .flatMap(List::stream)
                .map(record -> {
                    AuthHistory authHistory = new AuthHistory();
                    authHistory.setUriDomain(record.getUriDomain());
                    authHistory.setPrincipalDomain(record.getPrincipalDomain());
                    authHistory.setPrincipalName(record.getPrincipalName());
                    authHistory.setEndpoint(record.getEndpoint());
                    authHistory.setTimestamp(getAuthHistoryTimeStamp(record));
                    authHistory.setTtl(record.getTtl());
                    return authHistory;
                })
                .collect(Collectors.toList());
    }

    Timestamp getAuthHistoryTimeStamp(AuthHistoryDynamoDBRecord authHistoryDynamoDBRecord) {
        try {
            SimpleDateFormat formatter = new SimpleDateFormat("dd/MMM/yyyy:HH:mm:ss", Locale.ENGLISH);
            formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
            Date date = formatter.parse(authHistoryDynamoDBRecord.getTimestamp());
            return Timestamp.fromDate(date);
        } catch (ParseException e) {
            LOGGER.error("Error parsing timestamp for authHistoryDynamoDBRecord, timestamp will be empty: {}", authHistoryDynamoDBRecord);
            return null;
        }
    }
}
