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
package com.yahoo.athenz.common.server.log;

import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;

import org.mockito.Mockito;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import org.testng.annotations.Test;
import org.testng.annotations.BeforeClass;

import static org.testng.Assert.*;

import com.yahoo.athenz.common.server.log.AthenzRequestLog;
import com.yahoo.athenz.common.server.log.AuditLogMsgBuilder;
import com.yahoo.athenz.common.server.log.AuditLogger;
import com.yahoo.rdl.Timestamp;

public class AthenzRequestLogTest {

    @Mock Request mockRequest;

    long currentTimeMillis = System.currentTimeMillis();
    java.util.Enumeration<String> testHeadersEnum = null;

    final static String CRED_IN_ERROR = "v=S1;d=cd.project;n=nfl;h=somehost.somecompany.com;a=saltvalue;t=1447361732;e=1447361742";

    final static String CRED_ATTR_ERROR = ":error: PrincipalAuthority:authenticate: service token validation failure: Token:validate: token=v=S1;d=cd.project;n=nfl;h=somehost.somecompany.com;a=saltvalue;t=1447361732;e=1447361742 : has expired time=1447361742 : current time=1447465088 : credential=" + CRED_IN_ERROR;

    final static java.util.Set<String> auditLogMsgs = new java.util.HashSet<String>();
    final static java.util.Set<String> jettyLogMsgs = new java.util.HashSet<String>();

    static AuditLogger auditLogger;

    static org.eclipse.jetty.util.log.Logger jettyLogger;

    @BeforeClass
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        Mockito.when(mockRequest.getRemoteAddr()).thenReturn("11.16.20.15");
        Mockito.when(mockRequest.getLocalName()).thenReturn("FakeTestHostName");
        Mockito.when(mockRequest.getServerPort()).thenReturn(4666);
        Mockito.when(mockRequest.getRequestURI()).thenReturn("/domain/jupiter/moons");
        Mockito.when(mockRequest.getRemoteUser()).thenReturn("FakeUserId");
        Mockito.when(mockRequest.getMethod()).thenReturn("GET");
        Mockito.when(mockRequest.getAttribute("com.yahoo.athenz.auth.credential.error")).thenReturn(CRED_ATTR_ERROR);
        Mockito.when(mockRequest.getTimeStamp()).thenReturn(currentTimeMillis);

        java.util.Hashtable<String, String> reqHeaders = new java.util.Hashtable<>();
        testHeadersEnum = reqHeaders.keys();
        Mockito.when(mockRequest.getHeaderNames()).thenReturn(testHeadersEnum);
        org.eclipse.jetty.http.HttpURI httpUri = new org.eclipse.jetty.http.HttpURI();
        Mockito.when(mockRequest.getHttpURI()).thenReturn(httpUri);

        auditLogger = new AuditLogger() {
            @Override
            public void log(String msg, String msgVersion) {
                auditLogMsgs.add(msg);
            }

            @Override
            public void log(AuditLogMsgBuilder msgBldr) {
                auditLogMsgs.add(msgBldr.build());
            }

        };

        jettyLogger = new org.eclipse.jetty.util.log.Logger() {
            public String getName() { return "TestLogger"; }
            public void warn(String msg, Object... args) {
                jettyLogMsgs.add(msg);
            }
            public void warn(Throwable thrown) { }
            public void warn(String msg, Throwable thrown) {}
            public void info(String msg, Object... args) {}
            public void info(Throwable thrown) {}
            public void info(String msg, Throwable thrown) {}
            public boolean isDebugEnabled() { return true; }
            public void setDebugEnabled(boolean enabled) {}
            public void debug(String msg, Object... args) {}
            public void debug(String msg, long value) {}
            public void debug(Throwable thrown) {}
            public void debug(String msg, Throwable thrown) {}
            public org.eclipse.jetty.util.log.Logger getLogger(String name) { return this; }
            public void ignore(Throwable ignored) {}
        };

    }

    @Test
    public void testGetAuditLogMsgBuilder() {
        AthenzRequestLog log = new AthenzRequestLog();
        AuditLogMsgBuilder msgBldr = log.getAuditLogMsgBuilder(mockRequest);

        String httpMethod = msgBldr.whatMethod();
        assertTrue(httpMethod.equals("GET"), httpMethod);

        String who = msgBldr.who();
        assertTrue(who.equals(CRED_IN_ERROR), who);

        String why = msgBldr.why();
        assertTrue(why.equals(AthenzRequestLog.AUDIT_LOG_CRED_REF), why);

        String api =  msgBldr.whatApi();
        assertTrue(api.equals("/domain/jupiter/moons"), api);

        String when = msgBldr.when();
        Timestamp ts = Timestamp.fromMillis(currentTimeMillis);
        assertTrue(ts.toString().equals(when), when);

        String remoteAddr = msgBldr.clientIp();
        assertTrue(remoteAddr.equals("11.16.20.15"), remoteAddr);

        String where = msgBldr.where();
        assertTrue(where.contains("FakeTestHostName"), where);
        assertTrue(where.contains("4666"), where);

        String entity = msgBldr.whatEntity();
        assertTrue(entity.equals(AthenzRequestLog.AUDIT_CRED_ERROR_ATTR), entity);

        String credErr = msgBldr.whatDetails();
        assertTrue(credErr.equals("CRED_ERROR=(" + CRED_ATTR_ERROR + ");REMOTEUSER=(FakeUserId);"), credErr);
    }

    @Test
    public void testLogWithAuditLogger() {
        
        long bytesSent     = 4 * 1024 * 1024;
        String contentType = "text/html; charset=iso-8859-1";
        int responseCode   = 401;
        String reason      = "bad credential";

        Response mockResponse = Mockito.mock(Response.class);
        Mockito.when(mockResponse.getLongContentLength()).thenReturn(bytesSent);
        Mockito.when(mockResponse.getContentType()).thenReturn(contentType);
        Mockito.when(mockResponse.getStatus()).thenReturn(responseCode);
        Mockito.when(mockResponse.getReason()).thenReturn(reason);

        Timestamp ts = Timestamp.fromMillis(currentTimeMillis);
        String when = ts.toString();

        AthenzRequestLog log = new AthenzRequestLog("/dev/null", auditLogger);
        log.log(mockRequest, mockResponse);

        for (String val: auditLogMsgs) {
            assertTrue(val.contains("WHEN=(" + when), val);
            assertTrue(val.contains("WHO=(" + CRED_IN_ERROR + ")"), val);
            assertTrue(val.contains("WHY=(" + AthenzRequestLog.AUDIT_LOG_CRED_REF), val);
            assertTrue(val.contains("WHERE=(server-ip=FakeTestHostName"), val);
            assertTrue(val.contains("CLIENT-IP=(11.16.20.15)"), val);
            assertTrue(val.contains("WHAT-method=(GET)"), val);
            assertTrue(val.contains("WHAT-api=(/domain/jupiter/moons)"), val);
            assertTrue(val.contains("WHAT-entity=(" + AthenzRequestLog.AUDIT_CRED_ERROR_ATTR), val);
            assertTrue(val.contains("WHAT-details=(CRED_ERROR=(" + CRED_ATTR_ERROR + ");REMOTEUSER=(FakeUserId);"), val);
        }
    }

    @Test
    public void testLogWithoutAuditLogger() throws Exception {
        
        long bytesSent     = 4 * 1024 * 1024;
        String contentType = "text/html; charset=iso-8859-1";
        int responseCode   = 401;
        String reason      = "bad credential";

        Response mockResponse = Mockito.mock(Response.class);
        Mockito.when(mockResponse.getLongContentLength()).thenReturn(bytesSent);
        Mockito.when(mockResponse.getContentType()).thenReturn(contentType);
        Mockito.when(mockResponse.getStatus()).thenReturn(responseCode);
        Mockito.when(mockResponse.getReason()).thenReturn(reason);

        Timestamp ts = Timestamp.fromMillis(currentTimeMillis);
        String when = ts.toString();

        AthenzRequestLog log = new AthenzRequestLog() {
            protected org.eclipse.jetty.util.log.Logger getBackupLogger() {
                return jettyLogger;
            }
        };
        log.log(mockRequest, mockResponse);

        for (String val: jettyLogMsgs) {
            assertTrue(val.contains("WHEN=(" + when), val);
            assertTrue(val.contains("WHO=(" + CRED_IN_ERROR + ")"), val);
            assertTrue(val.contains("WHY=(" + AthenzRequestLog.AUDIT_LOG_CRED_REF), val);
            assertTrue(val.contains("WHERE=(server-ip=FakeTestHostName"), val);
            assertTrue(val.contains("CLIENT-IP=(11.16.20.15)"), val);
            assertTrue(val.contains("WHAT-method=(GET)"), val);
            assertTrue(val.contains("WHAT-api=(/domain/jupiter/moons)"), val);
            assertTrue(val.contains("WHAT-entity=(" + AthenzRequestLog.AUDIT_CRED_ERROR_ATTR), val);
            assertTrue(val.contains("WHAT-details=(CRED_ERROR=(" + CRED_ATTR_ERROR + ");REMOTEUSER=(FakeUserId);"), val);
        }
    }

    @Test
    public void testGetAuditLogMsgBuilderFileNameOnly() {
        AthenzRequestLog log = new AthenzRequestLog("/dev/null");
        assertNotNull(log);
    }
}
