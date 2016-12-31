/**
 * Copyright 2016 Yahoo Inc.
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

import com.yahoo.athenz.common.server.log.AuditLogFactory;
import com.yahoo.athenz.common.server.log.AuditLogMsgBuilder;
import com.yahoo.athenz.common.server.log.AuditLogger;

import org.testng.annotations.BeforeClass;


public class AuditLoggerTest {
    
    protected static AuditLogger auditLogger;
    
    final static String MSGVERS = "VERS=(test);";
    
    @BeforeClass
    public static synchronized void setUp() throws Exception {
        auditLogger = new AuditLogger() {
            @Override
            public void log(String msg, String msgVersion) {
                Assert.assertTrue(msg != null);
            }

            @Override
            public void log(AuditLogMsgBuilder msgBldr) {  
                Assert.assertTrue(msgBldr.build() != null);
            }
            
        };
    }

    @Test
    public void testLogFactoryDefault() {
        AuditLogger logger = AuditLogFactory.getLogger();
        logger.log("Default logger succeeds", MSGVERS);
    }

    @Test
    public void testLogFactoryString() {
        String auditLoggerClassName = "com.yahoo.athenz.common.server.log.impl.TestLogger";
        try {
            AuditLogger logger = AuditLogFactory.getLogger(auditLoggerClassName);
            logger.log("TestLogger succeeds", null);
            String dataStr = logger.getClass().getName();
            Assert.assertTrue(dataStr.equals(auditLoggerClassName), "classname=" + dataStr);
        } catch (Exception exc) {
            Assert.fail("Should have created the Logger=TestLogger with default constructor", exc);
        }
    }
    
    @Test
    public void testLogFactoryFalseParam() {
        String auditLoggerClassName = "com.yahoo.athenz.common.server.log.impl.TestLogger";
        Object param = new Boolean(false);
        try {
            AuditLogger logger = AuditLogFactory.getLogger(auditLoggerClassName, param);
            logger.log("TestLogger succeeds", MSGVERS);
            String dataStr = logger.getClass().getName();
            Assert.assertTrue(dataStr.equals(auditLoggerClassName), "classname=" + dataStr);
        } catch (Exception exc) {
            Assert.fail("Should have created the Logger=TestLogger with constructor taking param=" + param, exc);
        }
    }
    
    @Test
    public void testLogFactoryTrueParam() {
        String auditLoggerClassName = "com.yahoo.athenz.common.server.log.impl.TestLogger";
        Object param = new Boolean(true);
        try {
            AuditLogger logger = AuditLogFactory.getLogger(auditLoggerClassName, param);
            logger.log("TestLogger should not succeed", null);
            Assert.fail("Should have thrown exception, Logger=TestLogger for  param=" + param);
        } catch (Exception exc) {
            Assert.assertTrue(exc.getMessage().contains("TestLogger should not succeed"), "Should have thrown exception, Logger=TestLogger with constructor taking param=" + param);
        }
    }

    @Test
    public void testLogString() {
        auditLogger.log("testLog", null);
    }
    
    @Test
    public void testLogMsgBuilder() {
        AuditLogMsgBuilder msgBldr = AuditLogFactory.getMsgBuilder();
        auditLogger.log(msgBldr);
    }
}
