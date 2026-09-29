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

import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.common.server.log.AuditLogHistoryQuery;
import com.yahoo.athenz.common.server.log.AuditLogMsgBuilder;
import com.yahoo.athenz.common.server.log.AuditLogger;
import com.yahoo.athenz.common.server.log.AuditLoggerFactory;

import com.yahoo.rdl.Timestamp;
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

    @Test
    public void testGetDomainAuditLogHistoryDefault() throws ServerResourceException {
        AuditLoggerFactory auditLoggerFactory = new DefaultAuditLoggerFactory();
        AuditLogger logger = auditLoggerFactory.create();
        Assert.assertNull(logger.getDomainAuditLogHistory(new AuditLogHistoryQuery().setDomainName("athenz")));
    }

    @Test
    public void testAuditLogHistoryQuery() {
        Timestamp startTime = Timestamp.fromMillis(1655282257000L);
        Timestamp endTime = Timestamp.fromMillis(1655292257000L);
        AuditLogHistoryQuery query = new AuditLogHistoryQuery().setDomainName("athenz")
                .setApi("putrole").setEntity("readers").setPrincipal("user.joe")
                .setStartTime(startTime).setEndTime(endTime).setLimit(100);
        Assert.assertEquals(query.getDomainName(), "athenz");
        Assert.assertEquals(query.getApi(), "putrole");
        Assert.assertEquals(query.getEntity(), "readers");
        Assert.assertEquals(query.getPrincipal(), "user.joe");
        Assert.assertEquals(query.getStartTime(), startTime);
        Assert.assertEquals(query.getEndTime(), endTime);
        Assert.assertEquals(query.getLimit(), 100);
    }
}
