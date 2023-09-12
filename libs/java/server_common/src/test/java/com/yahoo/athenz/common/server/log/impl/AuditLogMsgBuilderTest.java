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

import java.time.Instant;

import org.testng.Assert;
import org.testng.annotations.Test;

import com.yahoo.athenz.common.server.log.AuditLogMsgBuilder;
import com.yahoo.athenz.common.server.log.AuditLogger;
import com.yahoo.athenz.common.server.log.AuditLoggerFactory;

/**
 * Test all API of AuditLogMsgBuilder.
 * Test the getMsgBuilder() API of AuditLogFactory.
 */
public class AuditLogMsgBuilderTest {

    private static final String ZMS_USER_DOMAIN = "athenz.user_domain";
    private static final String USER_DOMAIN = System.getProperty(ZMS_USER_DOMAIN, "user");
    
    private static final String TOKEN_STR = "v=U1;d=" + USER_DOMAIN + ";n=roger;h=somehost.somecompany.com;a=666;t=1492;e=2493;s=signature;";

    private DefaultAuditLogMsgBuilder starter(final String whatApi) {
        AuditLoggerFactory auditLoggerFactory = new DefaultAuditLoggerFactory();
        AuditLogger logger = auditLoggerFactory.create();
        AuditLogMsgBuilder msgBldr = logger.getMsgBuilder();
        String dataStr = Instant.now().toString();
        msgBldr.who(TOKEN_STR).when(dataStr).clientIp("12.12.12.12").whatApi(whatApi);
        return (DefaultAuditLogMsgBuilder)msgBldr;
    }
    
    @Test
    public void testWho() {
        DefaultAuditLogMsgBuilder msgBldr = starter("testWho");
        String dataStr = "me?";
        msgBldr.who(dataStr);
        Assert.assertEquals(msgBldr.who(), dataStr, "who string=" + msgBldr.who());
    }
    
    @Test
    public void testWhy() {
        DefaultAuditLogMsgBuilder msgBldr = starter("testWhy");
        String dataStr = "not?";
        msgBldr.why(dataStr);
        Assert.assertEquals(msgBldr.why(), dataStr, "why string=" + msgBldr.why());
    }

    @Test
    public void testWhenString() {
        DefaultAuditLogMsgBuilder msgBldr = starter("testWhenString");
        String dataStr = Instant.now().toString();
        msgBldr.when(dataStr);
        Assert.assertEquals(msgBldr.when(), dataStr, "when string=" + msgBldr.when());
    }

    @Test
    public void testClientIp() {
        DefaultAuditLogMsgBuilder msgBldr = starter("testClientIp");
        String dataStr = "99.77.22.hup";
        msgBldr.clientIp(dataStr);
        Assert.assertEquals(msgBldr.clientIp(), dataStr, "clientIp string=" + msgBldr.clientIp());
    }

    @Test
    public void testWhere() {
        DefaultAuditLogMsgBuilder msgBldr = starter("testWhere");
        String dataStr = "host1.athenz.com";
        msgBldr.where(dataStr);
        Assert.assertEquals(msgBldr.where(), dataStr, "where string=" + msgBldr.where());
    }

    @Test
    public void testWhatMethod() {
        DefaultAuditLogMsgBuilder msgBldr = starter("testWhatMethod");
        String dataStr = "PUT";
        msgBldr.whatMethod(dataStr);
        Assert.assertEquals(msgBldr.whatMethod(), dataStr, "whatMethod string=" + msgBldr.whatMethod());
    }

    @Test
    public void testWhatApi() {
        DefaultAuditLogMsgBuilder msgBldr = starter("testWhatApi");
        String dataStr = "putRole";
        msgBldr.whatApi(dataStr);
        Assert.assertEquals(msgBldr.whatApi(), dataStr, "whatApi string=" + msgBldr.whatApi());
    }

    @Test
    public void testWhatDomain() {
        DefaultAuditLogMsgBuilder msgBldr = starter("testWhatDomain");
        String dataStr = "sys.auth";
        msgBldr.whatDomain(dataStr);
        Assert.assertEquals(msgBldr.whatDomain(), dataStr, "whatDomain string=" + msgBldr.whatDomain());
    }

    @Test
    public void testWhatEntity() {
        DefaultAuditLogMsgBuilder msgBldr = starter("testWhatEntity");
        String dataStr = "readers";
        msgBldr.whatEntity(dataStr);
        Assert.assertEquals(msgBldr.whatEntity(), dataStr, "whatEntity string=" + msgBldr.whatEntity());
    }
    
    @Test
    public void testWhenEpoch() {
        DefaultAuditLogMsgBuilder msgBldr = starter("testWhenString");
        String dataStr = Instant.now().toString();
        msgBldr.when(dataStr);
        Instant instant = Instant.ofEpochMilli(Long.parseLong(msgBldr.whenEpoch()));
        String expected = msgBldr.when();
        String actual = instant.toString();
        Assert.assertEquals(msgBldr.when(), dataStr, "when string=" + msgBldr.when());

        // strip out the milliseconds parts and compare
        // jdk 8/11 give different precisions

        int idx = actual.lastIndexOf('.');
        final String actSecs = actual.substring(0, idx);
        idx = expected.lastIndexOf('.');
        final String expSecs = expected.substring(0, idx);
        Assert.assertEquals(actSecs, expSecs, "when string=" + msgBldr.when());
    }
    
    /**
     * Test method for {@link com.yahoo.athenz.common.server.log.impl.DefaultAuditLogMsgBuilder#build()}.
     */
    @Test
    public void testBuild() {
        AuditLogMsgBuilder msgBldr = starter("testBuild");
        String msg = msgBldr.build();
        Assert.assertTrue(msg.contains("WHAT-api=(testBuild)"), "Test string=" + msg);
        Assert.assertTrue(msg.contains("UUID="), "Test string=" + msg);
        Assert.assertTrue(msg.contains("WHO-fullname=(null)"), "Test string=" + msg);
        Assert.assertTrue(msg.contains("WHEN-epoch="), "Test string=" + msg);
        // when version tag is not null
        Assert.assertTrue(msgBldr.versionTag().contains("VERS=(athenz-def-1.0);"));
    }

    @Test
    public void testSetReplaceMethods() {
        AuditLogMsgBuilder msgBldr = starter("testBuild");
        Assert.assertNotNull(msgBldr.whatDetails("testWhatDetails"));
        Assert.assertEquals(msgBldr.whatDetails(), "testWhatDetails");

        Assert.assertNotNull(msgBldr.uuId("testUUID"));
        Assert.assertEquals(msgBldr.uuId(), "testUUID");

        Assert.assertNotNull(msgBldr.whoFullName("testWhoFullName"));
        Assert.assertEquals(msgBldr.whoFullName(), "testWhoFullName");
    }

    @Test
    public void testDefaultAuditLogger() {
        AuditLogger auditLogger = new DefaultAuditLogger("testLogger");
        AuditLogMsgBuilder msgBldr = auditLogger.getMsgBuilder();
        auditLogger.log(msgBldr);
        auditLogger.log(null);
    }
}
