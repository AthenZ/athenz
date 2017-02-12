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

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.eclipse.jetty.server.NCSARequestLog;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.log.Logger;

import com.yahoo.athenz.common.server.util.ServletRequestUtil;

public class AthenzRequestLog extends NCSARequestLog {

    protected static final Logger LOG = Log.getLogger(AthenzRequestLog.class);

    static final String AUDIT_CRED_ERROR_ATTR = "com.yahoo.athenz.auth.credential.error";
    static final String AUDIT_LOG_CRED_REF = "Authority Credential Error: Request Access Log";
    
    static final Pattern AUDIT_CRED_ERROR_PAT_WHO = Pattern.compile(".*(credential=)(.*)");
    public static final String REQUEST_PRINCIPAL = "com.yahoo.athenz.auth.principal";
    
    private AuditLogger auditLogger = null;
    
    public AthenzRequestLog() {
    }

    public AthenzRequestLog(String filename) {
        this(filename, null);
    }
    
    public AthenzRequestLog(String filename, AuditLogger auditLogger) {
        super(filename);
        this.auditLogger = auditLogger;
    }

    /**
     * Helper method useful for over-riding in test cases.
     */
    protected Logger getBackupLogger() {
        return LOG;
    }
    
    @Override
    public void log(final Request request, final Response response) {
        
        // first log our standard access entry
        
        super.log(request, response);
       
        // if this was a request that failed authentication and
        // was never got to be processed by the server, let's
        // add to our audit log before returning
        
        AuditLogMsgBuilder msgBldr = getAuditLogMsgBuilder(request);
        if (msgBldr != null) {
            if (auditLogger == null) {
                getBackupLogger().warn(msgBldr.build());
            } else {
                auditLogger.log(msgBldr);
            }
        }
    }
    
    @Override
    public void logExtended(StringBuilder b, Request request, Response response)
            throws IOException {
        
        super.logExtended(b, request, response);
        
        Object principal = request.getAttribute(REQUEST_PRINCIPAL);
        if (principal == null) {
            b.append(" \"-\" ");
        } else {
            b.append(" \"");
            b.append(principal.toString());
            b.append("\" ");
        }
        
        long requestLength = request.getContentLengthLong();
        if (requestLength >= 0) {
            if (requestLength > 99999) {
                b.append(requestLength);
            } else {
                if (requestLength > 9999) {
                    b.append((char) ('0' + ((requestLength / 10000) % 10)));
                }
                if (requestLength > 999) {
                    b.append((char) ('0' + ((requestLength / 1000) % 10)));
                }
                if (requestLength > 99) {
                    b.append((char) ('0' + ((requestLength / 100) % 10)));
                }
                if (requestLength > 9) {
                    b.append((char) ('0' + ((requestLength / 10) % 10)));
                }
                b.append((char) ('0' + (requestLength) % 10));
            }
        } else {
            b.append('-');
        }
    }
    /*
     * Parse authenticate credential error message for token string.
     * If found, return the token string, else null.
     */
    static String getWhoFromErrorMsg(String errMsg) {
        // look for "credential="
        CharSequence charSeq = errMsg.subSequence(0, errMsg.length());
        Matcher pm = AUDIT_CRED_ERROR_PAT_WHO.matcher(charSeq);
        if (pm.matches() && pm.groupCount() >= 2) {
            // we want group number 2, see AUDIT_CRED_ERROR_PAT_WHO for defined groups
            return pm.group(2);
        }
        return null;
    }
    
    AuditLogMsgBuilder getAuditLogMsgBuilder(final Request request) {
        Object credErr = request.getAttribute(AUDIT_CRED_ERROR_ATTR);
        if (credErr == null) {
            return null;
        }

        AuditLogMsgBuilder msgBldr = AuditLogFactory.getMsgBuilder();
        String httpMethod = request.getMethod();
        msgBldr.whatMethod(httpMethod);

        String details = credErr.toString();
        String who = getWhoFromErrorMsg(details);
        if (who != null) {
            msgBldr.who(who);
        } else {
            msgBldr.who("UNKNOWN principal: please see WHAT details");
        }

        msgBldr.why(AUDIT_LOG_CRED_REF);
        msgBldr.whatApi(request.getRequestURI());

        msgBldr.when(ServletRequestUtil.getTimeStamp(request));
        msgBldr.clientIp(ServletRequestUtil.getRemoteAddress(request));

        msgBldr.whereIp(request.getLocalName());
        msgBldr.whereHttpsPort(Integer.toString(request.getServerPort()));
        msgBldr.whatEntity(AUDIT_CRED_ERROR_ATTR);

        StringBuilder sb  = new StringBuilder(512);
        sb.append("CRED_ERROR=(").append(details).append(");");
        String remoteUser = request.getRemoteUser();
        if (remoteUser != null) {
            sb.append("REMOTEUSER=(").append(remoteUser).append(");");
        }

        msgBldr.whatDetails(sb.toString());
        return msgBldr;
    }
}
