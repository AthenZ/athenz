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
}
