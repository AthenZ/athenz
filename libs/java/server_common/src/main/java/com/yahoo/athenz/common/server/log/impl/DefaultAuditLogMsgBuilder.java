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
import java.util.Objects;

import com.fasterxml.uuid.EthernetAddress;
import com.fasterxml.uuid.Generators;
import com.fasterxml.uuid.impl.TimeBasedGenerator;
import com.yahoo.athenz.common.server.log.AuditLogMsgBuilder;

/*
 * Default implementation that can be inherited from.
 * Builds the Audit logging message to be passed to the AuditLog interface.
 * The log message built by this class can be parsed into a Struct (see parse()).
 * Example string built:
 *   VERS=(athenz-def-1.0);UUID=(391c0ed4-ce6c-11e8-bb3c-dafc29a0b98f);WHEN=(2015-04-02T18:30:58.441Z);WHO=(v=U1;d=user;n=jdoe);
 *   WHY=(audittest);WHERE=(server-ip=localhost,server-https-port=0,server-http-port=10080);
 *   CLIENT-IP=(MOCKCLIENT_HOST_NAME);WHAT-method=(PUT);WHAT-api=(puttenancy);
 *   WHAT-domain=(AddTenancyDom1);WHAT-entity=(tenancy.coretech.storage.reader);
 *   WHAT-details=({assertions: [{role: "AddTenancyDom1:role.admin", action: "ASSUME_ROLE", resource: "coretech:role.storage.tenant.AddTenancyDom1.reader"}], modified: "2015-04-02T18:30:58.441Z", name: "AddTenancyDom1:policy.tenancy.coretech.storage.reader"});
 */
public class DefaultAuditLogMsgBuilder implements AuditLogMsgBuilder {

    // Keys used in Struct returned by parse() method
    //
    // These keys will contain a String value
    public static final String PARSE_UUID = "UUID";
    public static final String PARSE_VERS = "VERS";
    public static final String PARSE_WHEN = "WHEN";
    public static final String PARSE_WHEN_EPOCH = "WHEN-epoch";
    public static final String PARSE_WHO  = "WHO";
    public static final String PARSE_WHY  = "WHY";
    public static final String PARSE_WHERE = "WHERE";
    public static final String PARSE_CLIENT_IP = "CLIENT-IP";
    public static final String PARSE_WHAT_METH = "WHAT-method";
    public static final String PARSE_WHAT_API  = "WHAT-api";
    public static final String PARSE_WHAT_DOM  = "WHAT-domain";
    public static final String PARSE_WHAT_ENT  = "WHAT-entity";
    public static final String PARSE_WHO_FULL_NAME  = "WHO-fullname";

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
    protected String uuid = null;        // unique identifier
    protected String who = null;         // The calling client/user requesting the change. Ex: "user.roger"
    protected String why = null;         // The audit reference or SOX ticket number.
    protected String clientIp = null;    // The IP address of the calling client(who).
    protected String when     = null;    // date-time in UTC
    protected String whenEpoch     = null;    // date-time epoch timestamp for types that do not support datetime
    protected String where    = null;    // The server hostname that received the requests
    protected String whatMethod  = null; // This is the REST method, ie. "PUT" or "POST", etc
    protected String whatApi     = null; // This is the server public method serving the request, ex: "putRole"
    protected String whatDomain  = null; // This is the Athenz domain being changed, ex: "xobni"
    protected String whatEntity  = null; // This is the entity in the Athenz domain being changed.
    protected String whatDetails = null; // This will contain specifics of the entity(whatEntity) that was changed.
    protected String whoFullName = null; // Full name of the calling client/user requesting the change. Ex: "roger"

    // Version of the log message produced. In case newer versions of the message creation
    // are implemented later.
    //
    protected String messageVersion = "athenz-def-1.0";
    protected String versionTag     = null;
    
    static final String NULL_STR = "null"; // place holder key word used for missing values
    static final int    SB_MIN_SIZE_INIT = 128;
    static final int    SB_MED_SIZE_INIT = 512;
    static final int    SB_MAX_SIZE_INIT = 1024;

    private static final TimeBasedGenerator UUIDV1 = Generators.timeBasedGenerator(EthernetAddress.fromInterface());

    public DefaultAuditLogMsgBuilder() {
    }

    /* (non-Javadoc)
     * @see com.yahoo.athenz.common.server.log.AuditLogMsgBuilder#versionTag()
     */
    public String versionTag() {
        if (versionTag == null) {
            versionTag = PARSE_VERS + "=(" + messageVersion + ");";
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
     * @see com.yahoo.athenz.common.server.log.AuditLogMsgBuilder#where(java.lang.String)
     */
    @Override
    public AuditLogMsgBuilder where(String whereVal) {
        this.where = whereVal;
        return this;
    }

    /* (non-Javadoc)
     * @see com.yahoo.athenz.common.server.log.AuditLogMsgBuilder#where()
     */
    @Override
    public String where() {
        if (where == null) {
            where = NULL_STR;
        }
        return where;
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
        return versionTag() 
                + PARSE_UUID + "=(" + uuId() + ");" 
                + PARSE_WHEN + "=(" + when() + ");"
                + PARSE_WHO + "=(" + who() + ");"
                + PARSE_WHY + "=(" + why() + ");"
                + PARSE_WHERE + "=(" + where() + ");"
                + PARSE_CLIENT_IP + "=(" + clientIp() + ");"
                + PARSE_WHAT_METH + "=(" + whatMethod() + ");"
                + PARSE_WHAT_API + "=(" + whatApi() + ");"
                + PARSE_WHAT_DOM + "=(" + whatDomain() + ");"
                + PARSE_WHAT_ENT + "=(" + whatEntity() + ");"
                + PARSE_WHAT_DETAILS + "=(" + whatDetails() + ");"
                + PARSE_WHO_FULL_NAME + "=(" + whoFullName() + ");"
                + PARSE_WHEN_EPOCH + "=(" + whenEpoch() + ");"
                ;
    }

    public String whenEpoch() {
        if (when == null) {
            return NULL_STR;
        }
        //Example: 2018-10-23T19:15:28.395Z
        return String.valueOf(Instant.parse(when).toEpochMilli());
    }

    @Override
    public AuditLogMsgBuilder uuId(String UUID) {
        this.uuid = UUID;
        return this;
    }

    @Override
    public String uuId() {
        if (this.uuid == null) {
            return UUIDV1.generate().toString();
        }
        return this.uuid;
    }

    @Override
    public AuditLogMsgBuilder whoFullName(String whoVal) {
        this.whoFullName = whoVal;
        return this;
    }

    @Override
    public String whoFullName() {
        return Objects.requireNonNullElse(this.whoFullName, NULL_STR);
    }

}

