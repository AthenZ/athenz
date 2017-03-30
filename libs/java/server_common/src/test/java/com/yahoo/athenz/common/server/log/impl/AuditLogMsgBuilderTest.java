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

import com.yahoo.athenz.common.server.log.AuditLogMsgBuilder;
import com.yahoo.athenz.common.server.log.AuditLogger;
import com.yahoo.athenz.common.server.log.AuditLoggerFactory;
import com.yahoo.athenz.common.server.log.impl.DefaultAuditLogMsgBuilder;

/**
 * Test all API of AuditLogMsgBuilder.
 * Test the getMsgBuilder() API of AuditLogFactory.
 */
public class AuditLogMsgBuilderTest {

    private static final String ZMS_USER_DOMAIN = "athenz.user_domain";
    private static final String USER_DOMAIN = System.getProperty(ZMS_USER_DOMAIN, "user");
    
    static String TOKEN_STR = "v=U1;d=" + USER_DOMAIN + ";n=roger;h=somehost.somecompany.com;a=666;t=1492;e=2493;s=signature;";

    DefaultAuditLogMsgBuilder starter(final String whatApi) {
        AuditLoggerFactory auditLoggerFactory = new DefaultAuditLoggerFactory();
        AuditLogger logger = auditLoggerFactory.create();
        AuditLogMsgBuilder msgBldr = logger.getMsgBuilder();
        msgBldr.who(TOKEN_STR).when("now-timestamp").clientIp("12.12.12.12").whatApi(whatApi);
        return (DefaultAuditLogMsgBuilder)msgBldr;
    }
    
    @Test
    public void testWho() {
        DefaultAuditLogMsgBuilder msgBldr = starter("testWho");
        String dataStr = "me?";
        msgBldr.who(dataStr);
        Assert.assertTrue(msgBldr.who().equals(dataStr), "who string=" + msgBldr.who());
    }
    
    @Test
    public void testWhy() {
        DefaultAuditLogMsgBuilder msgBldr = starter("testWhy");
        String dataStr = "not?";
        msgBldr.why(dataStr);
        Assert.assertTrue(msgBldr.why().equals(dataStr), "why string=" + msgBldr.why());
    }

    @Test
    public void testWhenString() {
        DefaultAuditLogMsgBuilder msgBldr = starter("testWhenString");
        String dataStr = "now?";
        msgBldr.when(dataStr);
        Assert.assertTrue(msgBldr.when().equals(dataStr), "when string=" + msgBldr.when());
    }

    @Test
    public void testClientIp() {
        DefaultAuditLogMsgBuilder msgBldr = starter("testClientIp");
        String dataStr = "99.77.22.hup";
        msgBldr.clientIp(dataStr);
        Assert.assertTrue(msgBldr.clientIp().equals(dataStr), "clientIp string=" + msgBldr.clientIp());
    }

    @Test
    public void testWhere() {
        DefaultAuditLogMsgBuilder msgBldr = starter("testWhere");
        String dataStr = "host1.athenz.com";
        msgBldr.where(dataStr);
        Assert.assertTrue(msgBldr.where().equals(dataStr), "where string=" + msgBldr.where());
    }

    @Test
    public void testWhatMethod() {
        DefaultAuditLogMsgBuilder msgBldr = starter("testWhatMethod");
        String dataStr = "PUT";
        msgBldr.whatMethod(dataStr);
        Assert.assertTrue(msgBldr.whatMethod().equals(dataStr), "whatMethod string=" + msgBldr.whatMethod());
    }

    @Test
    public void testWhatApi() {
        DefaultAuditLogMsgBuilder msgBldr = starter("testWhatApi");
        String dataStr = "putRole";
        msgBldr.whatApi(dataStr);
        Assert.assertTrue(msgBldr.whatApi().equals(dataStr), "whatApi string=" + msgBldr.whatApi());
    }

    @Test
    public void testWhatDomain() {
        DefaultAuditLogMsgBuilder msgBldr = starter("testWhatDomain");
        String dataStr = "sys.auth";
        msgBldr.whatDomain(dataStr);
        Assert.assertTrue(msgBldr.whatDomain().equals(dataStr), "whatDomain string=" + msgBldr.whatDomain());
    }

    @Test
    public void testWhatEntity() {
        DefaultAuditLogMsgBuilder msgBldr = starter("testWhatEntity");
        String dataStr = "readers";
        msgBldr.whatEntity(dataStr);
        Assert.assertTrue(msgBldr.whatEntity().equals(dataStr), "whatEntity string=" + msgBldr.whatEntity());
    }
    
    /**
     * Test method for {@link com.yahoo.athenz.common.server.log.impl.DefaultAuditLogMsgBuilder#build()}.
     */
    @Test
    public void testBuild() {
        AuditLogMsgBuilder msgBldr = starter("testBuild");
        
        String msg = msgBldr.build();
        Assert.assertTrue(msg.contains("WHAT-api=(testBuild)"), "Test string=" + msg);
    }
}
