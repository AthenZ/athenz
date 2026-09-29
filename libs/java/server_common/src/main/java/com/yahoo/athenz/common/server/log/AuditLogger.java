/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.yahoo.athenz.common.server.log;

import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.zms.DomainAuditLog;

/**
 * Interface to perform audit logging. 
 * See {@link com.yahoo.athenz.common.server.log.AuditLoggerFactory#create()}
 */
public interface AuditLogger {
    /**
     * Perform logging of the given message.
     * @param logMsg message to be logged
     * @param msgVersionTag optional version tag of the message - may be null
     *                      If the message must be split into chunks then msgVersionTag
     *                      will be used prefixed to each chunk/partition.
     */
    void log(String logMsg, String msgVersionTag);
    
    /**
     * Log the message as built by the provided msgBldr.
     * @param msgBldr constructs message to be logged, contains version tag of the message
     */
    void log(AuditLogMsgBuilder msgBldr);
    
    /**
     * Get a log message builder
     * @return default AuditLogMsgBuilder instance
     */
    AuditLogMsgBuilder getMsgBuilder();

    /**
     * Retrieve the audit log history for the given domain. The records
     * must be filtered based on the provided query arguments and must be
     * sorted by the timestamp in descending order (most recent first).
     * The implementation must return at most query.getLimit() entries and
     * if there are more records matching the query, it must set the partial
     * flag to true to indicate that the result set is incomplete. The server
     * returns the object as is without any further processing.
     * The default implementation does not support retrieving history
     * and returns null.
     * @param query audit log history query arguments
     * @return domain audit log object or null if not supported
     * @throws ServerResourceException in case of any errors
     */
    default DomainAuditLog getDomainAuditLogHistory(AuditLogHistoryQuery query) throws ServerResourceException {
        return null;
    }
}
