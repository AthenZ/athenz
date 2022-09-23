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

import org.testng.Assert;
import org.testng.annotations.Test;

import com.yahoo.athenz.common.server.log.AuditLogMsgBuilder;
import com.yahoo.athenz.common.server.log.AuditLogger;
import com.yahoo.athenz.common.server.log.AuditLoggerFactory;

import org.testng.annotations.BeforeClass;


public class AuditLoggerTest {
    
    private static AuditLogger auditLogger;
    
    private final static String MSGVERS = "VERS=(test);";
    
    @BeforeClass
    public static synchronized void setUp() {
        auditLogger = new DefaultAuditLogger() {
            @Override
            public void log(String msg, String msgVersion) {
                Assert.assertNotNull(msg);
            }

            @Override
            public void log(AuditLogMsgBuilder msgBldr) {
                Assert.assertNotNull(msgBldr.build());
            }
            
        };
    }

    @Test
    public void testLogFactoryDefault() {
        AuditLoggerFactory auditLoggerFactory = new DefaultAuditLoggerFactory();
        AuditLogger logger = auditLoggerFactory.create();
        logger.log("Default logger succeeds", MSGVERS);
    }
    
    @Test
    public void testLogString() {
        auditLogger.log("testLog", null);
    }
    
    @Test
    public void testLogMsgBuilder() {
        AuditLoggerFactory auditLoggerFactory = new DefaultAuditLoggerFactory();
        AuditLogger logger = auditLoggerFactory.create();
        AuditLogMsgBuilder msgBldr = logger.getMsgBuilder();
        auditLogger.log(msgBldr);
    }
}
