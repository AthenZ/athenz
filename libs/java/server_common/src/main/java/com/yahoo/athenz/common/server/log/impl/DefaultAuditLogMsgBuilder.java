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

import java.util.regex.Pattern;

import com.yahoo.athenz.common.server.log.AuditLogMsgBuilder;

/*
 * Default implementation that can be inherited from.
 * Builds the Audit logging message to be passed to the AuditLog interface.
 * The log message built by this class can be parsed into a Struct (see parse()).
 * Example string built:
 *   VERS=(athenz-def-1.0);WHEN=(2015-04-02T18:30:58.441Z);WHO=(v=U1;d=user;n=jdoe);
 *   WHY=(audittest);WHERE=(server-ip=localhost,server-https-port=0,server-http-port=10080);
 *   CLIENT-IP=(MOCKCLIENT_HOST_NAME);WHAT-method=(PUT);WHAT-api=(puttenancy);
 *   WHAT-domain=(AddTenancyDom1);WHAT-entity=(tenancy.coretech.storage.reader);
 *   WHAT-details=({assertions: [{role: "AddTenancyDom1:role.admin", action: "ASSUME_ROLE", resource: "coretech:role.storage.tenant.AddTenancyDom1.reader"}], modified: "2015-04-02T18:30:58.441Z", name: "AddTenancyDom1:policy.tenancy.coretech.storage.reader"});
 */
public class DefaultAuditLogMsgBuilder implements AuditLogMsgBuilder {

    // Keys used in Struct returned by parse() method
    //
    // These keys will contain a String value
    public static final String PARSE_VERS = "VERS";
    public static final String PARSE_WHEN = "WHEN";
    public static final String PARSE_WHO  = "WHO";
    public static final String PARSE_WHY  = "WHY";
    public static final String PARSE_WHERE = "WHERE";
    public static final String PARSE_CLIENT_IP = "CLIENT-IP";
    public static final String PARSE_WHAT_METH = "WHAT-method";
    public static final String PARSE_WHAT_API  = "WHAT-api";
    public static final String PARSE_WHAT_DOM  = "WHAT-domain";
    public static final String PARSE_WHAT_ENT  = "WHAT-entity";

    // This key will contain a Struct value
    public static final String PARSE_WHAT_DETAILS = "WHAT-details";

    // These fields are found in the embedded Struct keyed by "WHAT-details"
    //
    // These fields contain a String
    public static final String PARSE_DETAILS_ADDED           = "ADDED";
    public static final String PARSE_DETAILS_REMOVED         = "REMOVED";
    public static final String PARSE_DETAILS_CHANGED         = "CHANGED";
    //
    // Each of these fields is an Array of Strings.
    //
    public static final String PARSE_DETAILS_ADDEDVALS       = "ADDED-VALUES";
    public static final String PARSE_DETAILS_REMOVEDVALS     = "REMOVED-VALUES";
    public static final String PARSE_DETAILS_FROMTOVALS      = "FROM-TO-VALUES";
    public static final String PARSE_DETAILS_EMB_ADDEDVALS   = "EMBEDDED-ADDED";
    public static final String PARSE_DETAILS_EMB_REMOVEDVALS = "EMBEDDED-REMOVED";

    // log message contains these fields - which parse combines into one field
    //
    public static final String PARSE_FROM = "FROM";
    public static final String PARSE_TO   = "TO";

    // data members used for log message fields
    //
    protected String who = null;         // The calling client/user requesting the change. Ex: "user.roger"
    protected String why = null;         // The audit reference or SOX ticket number.
    protected String clientIp = null;    // The IP address of the calling client(who).
    protected String when     = null;    // date-time in UTC
    protected String whereIp  = null;     // The IP address and ports of the server where it receives the requests at.
    protected String whereHttpsPort = null; // The server https port endpoint
    protected String whereHttpPort  = null; // The server http port endpoint
    protected String whatMethod  = null; // This is the REST method, ie. "PUT" or "POST", etc
    protected String whatApi     = null; // This is the server public method serving the request, ex: "putRole"
    protected String whatDomain  = null; // This is the Athenz domain being changed, ex: "xobni"
    protected String whatEntity  = null; // This is the entity in the Athenz domain being changed.
    protected String whatDetails = null; // This will contain specifics of the entity(whatEntity) that was changed.

    // Version of the log message produced. In case newer versions of the message creation
    // are implemented later.
    //
    protected String messageVersion = "athenz-def-1.0";
    protected String versionTag     = null;
    
    static final String NULL_STR = "null"; // place holder key word used for missing values
    static final int    SB_MIN_SIZE_INIT = 128;
    static final int    SB_MED_SIZE_INIT = 512;
    static final int    SB_MAX_SIZE_INIT = 1024;
    
    // setup for parsing log messages
    //
    static final String  GEN_FLD_PAT = "=\\(([^\\)]+)\\);.*";
    static final Pattern PAT_VERS = Pattern.compile(".*(" + PARSE_VERS + ")" + GEN_FLD_PAT);
    static final Pattern PAT_WHEN = Pattern.compile(".*(" + PARSE_WHEN + ")" + GEN_FLD_PAT);
    static final Pattern PAT_WHO  = Pattern.compile(".*(" + PARSE_WHO + ")" + GEN_FLD_PAT);
    static final Pattern PAT_WHY  = Pattern.compile(".*(" + PARSE_WHY + ")" + GEN_FLD_PAT);
    static final Pattern PAT_WHERE = Pattern.compile(".*(" + PARSE_WHERE + ")" + GEN_FLD_PAT);
    static final Pattern PAT_CLTIP = Pattern.compile(".*(" + PARSE_CLIENT_IP + ")" + GEN_FLD_PAT);
    static final Pattern PAT_WHAT_METH = Pattern.compile(".*(" + PARSE_WHAT_METH + ")" + GEN_FLD_PAT);
    static final Pattern PAT_WHAT_API  = Pattern.compile(".*(" + PARSE_WHAT_API + ")" + GEN_FLD_PAT);
    static final Pattern PAT_WHAT_DOM  = Pattern.compile(".*(" + PARSE_WHAT_DOM + ")" + GEN_FLD_PAT);
    static final Pattern PAT_WHAT_ENT  = Pattern.compile(".*(" + PARSE_WHAT_ENT + ")" + GEN_FLD_PAT);

    public DefaultAuditLogMsgBuilder() {
    }

    /* (non-Javadoc)
     * @see com.yahoo.athenz.common.server.log.AuditLogMsgBuilder#versionTag()
     */
    public String versionTag() {
        if (versionTag == null) {
            StringBuilder sb = new StringBuilder(SB_MIN_SIZE_INIT);
            sb.append(PARSE_VERS).append("=(").append(messageVersion).append(");");
            versionTag = sb.toString();
        }
        return versionTag;
    }
    
    /* (non-Javadoc)
     * @see com.yahoo.athenz.common.server.log.AuditLogMsgBuilder#who(java.lang.String)
     */
    @Override
    public AuditLogMsgBuilder who(String whoVal) {
        this.who = whoVal;
        return this;
    }
    
    /* (non-Javadoc)
     * @see com.yahoo.athenz.common.server.log.AuditLogMsgBuilder#who()
     */
    @Override
    public String who() { 
        if (who == null) {
            return NULL_STR;
        }
        return who;
    }

    /* (non-Javadoc)
     * @see com.yahoo.athenz.common.server.log.AuditLogMsgBuilder#why(java.lang.String)
     */
    @Override
    public AuditLogMsgBuilder why(String whyVal) {
        this.why = whyVal;
        return this;
    }
    
    /* (non-Javadoc)
     * @see com.yahoo.athenz.common.server.log.AuditLogMsgBuilder#why()
     */
    @Override
    public String why() {
        if (why == null) {
            return NULL_STR;
        }
        return why;
    }

    /* (non-Javadoc)
     * @see com.yahoo.athenz.common.server.log.AuditLogMsgBuilder#when(java.lang.String)
     */
    @Override
    public AuditLogMsgBuilder when(String whenVal) {
        this.when = whenVal;
        return this;
    }
    
    /* (non-Javadoc)
     * @see com.yahoo.athenz.common.server.log.AuditLogMsgBuilder#when()
     */
    @Override
    public String when() {
        if (when == null) {
            return NULL_STR;
        }
        return when;
    }

    /* (non-Javadoc)
     * @see com.yahoo.athenz.common.server.log.AuditLogMsgBuilder#clientIp(java.lang.String)
     */
    @Override
    public AuditLogMsgBuilder clientIp(String clientIpAddr) {
        this.clientIp = clientIpAddr;
        return this;
    }
    
    /* (non-Javadoc)
     * @see com.yahoo.athenz.common.server.log.AuditLogMsgBuilder#clientIp()
     */
    @Override
    public String clientIp() {
        if (clientIp == null) {
            return NULL_STR;
        }
        return clientIp;
    }

    /* (non-Javadoc)
     * @see com.yahoo.athenz.common.server.log.AuditLogMsgBuilder#whereIp(java.lang.String)
     */
    @Override
    public AuditLogMsgBuilder whereIp(String whereVal) {
        this.whereIp = whereVal;
        return this;
    }
    
    /* (non-Javadoc)
     * @see com.yahoo.athenz.common.server.log.AuditLogMsgBuilder#whereHttpsPort(java.lang.String)
     */
    @Override
    public AuditLogMsgBuilder whereHttpsPort(String whereVal) {
        this.whereHttpsPort = whereVal;
        return this;
    }
    
    /* (non-Javadoc)
     * @see com.yahoo.athenz.common.server.log.AuditLogMsgBuilder#whereHttpPort(java.lang.String)
     */
    @Override
    public AuditLogMsgBuilder whereHttpPort(String whereVal) {
        this.whereHttpPort = whereVal;
        return this;
    }

    // Ex: '{"server-ip":"198.177.62.9","server-https-port":"4453","server-http-port":"10080"}'
    /* (non-Javadoc)
     * @see com.yahoo.athenz.common.server.log.AuditLogMsgBuilder#where()
     */
    @Override
    public String where() {
        if (whereIp == null) {
            whereIp = NULL_STR;
        }
        StringBuilder sb = new StringBuilder(SB_MIN_SIZE_INIT);
        sb.append("server-ip=").append(whereIp);
        
        if (whereHttpsPort == null) {
            whereHttpsPort = NULL_STR;
        }
        sb.append(",server-https-port=").append(whereHttpsPort);
        
        if (whereHttpPort == null) {
            whereHttpPort = NULL_STR;
        }
        sb.append(",server-http-port=").append(whereHttpPort);

        return sb.toString();
    }

    /* (non-Javadoc)
     * @see com.yahoo.athenz.common.server.log.AuditLogMsgBuilder#whatMethod(java.lang.String)
     */
    @Override
    public AuditLogMsgBuilder whatMethod(String whatMethodVal) {
        this.whatMethod = whatMethodVal;
        return this;
    }
    
    /* (non-Javadoc)
     * @see com.yahoo.athenz.common.server.log.AuditLogMsgBuilder#whatMethod()
     */
    @Override
    public String whatMethod() {
        if (whatMethod == null) {
            return NULL_STR;
        }
        return whatMethod;
    }

    /* (non-Javadoc)
     * @see com.yahoo.athenz.common.server.log.AuditLogMsgBuilder#whatApi(java.lang.String)
     */
    @Override
    public AuditLogMsgBuilder whatApi(String whatApiVal) {
        this.whatApi = whatApiVal;
        return this;
    }
    
    /* (non-Javadoc)
     * @see com.yahoo.athenz.common.server.log.AuditLogMsgBuilder#whatApi()
     */
    @Override
    public String whatApi() {
        if (whatApi == null) {
            return NULL_STR;
        }
        return whatApi;
    }

    /* (non-Javadoc)
     * @see com.yahoo.athenz.common.server.log.AuditLogMsgBuilder#whatDomain(java.lang.String)
     */
    @Override
    public AuditLogMsgBuilder whatDomain(String whatDomainVal) {
        this.whatDomain = whatDomainVal;
        return this;
    }
    
    /* (non-Javadoc)
     * @see com.yahoo.athenz.common.server.log.AuditLogMsgBuilder#whatDomain()
     */
    @Override
    public String whatDomain() {
        if (whatDomain == null) {
            return NULL_STR;
        }
        return whatDomain;
    }

    /* (non-Javadoc)
     * @see com.yahoo.athenz.common.server.log.AuditLogMsgBuilder#whatEntity(java.lang.String)
     */
    @Override
    public AuditLogMsgBuilder whatEntity(String whatEntityVal) {
        this.whatEntity = whatEntityVal;
        return this;
    }
    
    /* (non-Javadoc)
     * @see com.yahoo.athenz.common.server.log.AuditLogMsgBuilder#whatEntity()
     */
    @Override
    public String whatEntity() {
        if (whatEntity == null) {
            return NULL_STR;
        }
        return whatEntity;
    }

    /* Set/replace the whatDetails field.
     * (non-Javadoc)
     * @see com.yahoo.athenz.common.server.log.AuditLogMsgBuilder#whatDetails(java.lang.String)
     */
    @Override
    public AuditLogMsgBuilder whatDetails(String whatDetailsVal) {
        this.whatDetails = whatDetailsVal;
        return this;
    }
    
    /* (non-Javadoc)
     * @see com.yahoo.athenz.common.server.log.AuditLogMsgBuilder#whatDetails()
     */
    @Override
    public String whatDetails() {
        if (whatDetails == null) {
            return NULL_STR;
        }
        return whatDetails;
    }
    
    /* (non-Javadoc)
     * @see com.yahoo.athenz.common.server.log.AuditLogMsgBuilder#build()
     */
    @Override
    public String build() {
        StringBuilder sb = new StringBuilder(SB_MAX_SIZE_INIT);
        sb.append(versionTag()).append(PARSE_WHEN).append("=(").append(when()).
            append(");"). append(PARSE_WHO).append("=(").append(who()).
            append(");").append(PARSE_WHY).append("=(").append(why()).
            append(");").append(PARSE_WHERE).append("=(").append(where()).
            append(");").append(PARSE_CLIENT_IP).append("=(").append(clientIp());
        sb.append(");").append(PARSE_WHAT_METH).append("=(").append(whatMethod()).append(");").append(PARSE_WHAT_API).append("=(");
        sb.append(whatApi()).append(");").append(PARSE_WHAT_DOM).append("=(").append(whatDomain()).append(");").append(PARSE_WHAT_ENT).append("=(");
        sb.append(whatEntity()).append(");").append(PARSE_WHAT_DETAILS).append("=(").append(whatDetails()).append(");");
        return sb.toString();
    }
}

