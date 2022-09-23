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
package com.yahoo.athenz.common.server.log.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.common.server.log.AuditLogMsgBuilder;
import com.yahoo.athenz.common.server.log.AuditLogger;

/**
 * This default implementation uses log4j API.
 * The default constructor depends on a logger named "AuditSoxLogger" specified in the logback.xml
 * The second constructor takes a name of the logger the caller wants to use.
 */
public class DefaultAuditLogger implements AuditLogger {

    /**
     * Configured logger named "AuditSoxLogger"
     */
    private static Logger AUDITLOGGER = LoggerFactory.getLogger("AuditSoxLogger");
    
    public DefaultAuditLogger() {
    }

    /**
     * Override the default logger with one named loggerName
     * @param loggerName name of the logger
     */
    public DefaultAuditLogger(String loggerName) {
        AUDITLOGGER = LoggerFactory.getLogger(loggerName);
    }
    
    /**
     * @see com.yahoo.athenz.common.server.log.AuditLogger#log(java.lang.String, java.lang.String)
     */
    @Override
    public void log(String logMsg, String msgVersionTag) {
        AUDITLOGGER.info(logMsg); // ignore msgVersionTag for this logger implementation
    }

    /* (non-Javadoc)
     * @see com.yahoo.athenz.common.server.log.AuditLogger#log(com.yahoo.athenz.common.server.log.AuditLogMsgBuilder)
     */
    @Override
    public void log(AuditLogMsgBuilder msgBldr) {
        if (msgBldr != null) {
            log(msgBldr.build(), msgBldr.versionTag());
        }
    }
    
    /*
     * Get the default AuditLogMsgBuilder implementation.
     */
    @Override
    public AuditLogMsgBuilder getMsgBuilder() {
        return new DefaultAuditLogMsgBuilder();
    }
}
