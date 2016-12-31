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

import java.util.Set;
import java.util.HashSet;
import java.util.Iterator;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

import com.yahoo.rdl.Struct;
import com.yahoo.rdl.Timestamp;
import com.yahoo.rdl.Value;
import com.yahoo.athenz.common.server.log.AuditLogMsgBuilder;
import com.yahoo.rdl.Array;

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
     * @see com.yahoo.athenz.common.server.log.AuditLogMsgBuilder#when(com.yahoo.data.Timestamp)
     */
    @Override
    public AuditLogMsgBuilder when(Timestamp ts) {
        return when(ts.toString());
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
     * @see com.yahoo.athenz.common.server.log.AuditLogMsgBuilder#whatDetails(java.lang.String, com.yahoo.data.Struct, com.yahoo.data.Struct)
     */   
    @Override
    public AuditLogMsgBuilder whatDetails(String tag, Struct origFields, Struct newFields) {
        return whatDetails(whatSubDetails(tag, origFields, newFields));
    }
    
    // Determines all differences between the Struct of original fields and the new one.
    // If the Struct contains a Struct field, this method will recur into that field.
    //
    String whatSubDetails(String tag, Struct origFields, Struct newFields) {
            
        Set<String> setChanged  = origFields.keySet();
        Set<String> setOldDiff  = new HashSet<String>(setChanged);
        Set<String> setNew      = newFields.keySet();
        Set<String> setNewDiff  = new HashSet<String>(setNew);
        setOldDiff.removeAll(setNewDiff); // gets a diff - contains Removed elements
        
        Set<String> setOld     = origFields.keySet();
        setNewDiff.removeAll(setOld); // gets a diff - contains Added elements
        // HAVE: partial diff, all removed and added elements
        
        // for the intersection of set of keys, find any changes to the values
        //
        StringBuilder changedSb = new StringBuilder(SB_MED_SIZE_INIT);
        changedSb.append(PARSE_DETAILS_CHANGED).append("=(");
        setChanged.retainAll(setNew); // the intersection of the 2 sets
        // if we have common keys, are the values different?
        boolean changedValsFound = false;
        for (Iterator<String> it = setChanged.iterator(); it != null && it.hasNext();) {
            String key = it.next();
            Object origVal = origFields.get(key);
            if (origVal instanceof Timestamp) {
                continue; // ignore timestamp fields
            }
            Object newVal  = newFields.get(key);
            if (Value.equals(origVal, newVal) == false) {
                // the values have changed for this key
                changedValsFound = true;
                if (origVal instanceof Array) {
                    StringBuilder addedSetSb   = new StringBuilder(SB_MED_SIZE_INIT);
                    addedSetSb.append(key + "=(").append(PARSE_DETAILS_ADDEDVALS).append("=(");
                    StringBuilder removedSetSb = new StringBuilder(SB_MED_SIZE_INIT);
                    removedSetSb.append(key + "=(").append(PARSE_DETAILS_REMOVEDVALS).append("=(");
                    
                    buildDiffArray((Array) origVal, (Array) newVal, addedSetSb, removedSetSb);
                    addedSetSb.append("));"); // end-of-<key>=
                    removedSetSb.append("));"); // end-of-<key>=
                    changedSb.append(addedSetSb.toString());
                    changedSb.append(removedSetSb.toString());
                } else if (origVal instanceof Struct) {
                    String subDetails = whatSubDetails(key, (Struct) origVal, (Struct) newVal);
                    changedSb.append(subDetails);
                } else {
                    changedSb.append(key + "=(").append(PARSE_FROM).append("=(").append(origVal);
                    changedSb.append(");").append(PARSE_TO).append("=(").append(newVal);
                    changedSb.append("));");  // end-of-<key>=
                }
            }
        }
        // HAVE: full diff, elements with changed values, removed elements, added elements

        // if user didnt specify a tag, we will use a default to keep syntax
        // consistent in the built string
        String prefix = tag == null ? "TAG=(" : tag + "=(";
        StringBuilder sb = new StringBuilder(SB_MED_SIZE_INIT);
        sb.append(prefix);
        
        if (setChanged.size() > 0) {  // HAVE: values were replaced
            if (!changedValsFound) {
                changedSb.append(NULL_STR);
            }
        }
        changedSb.append(");");  // end-of-CHANGED=
        sb.append(changedSb);
 
        sb.append(prefix).append(PARSE_DETAILS_REMOVED + "=(");
        buildDiffKeys(setOldDiff, origFields, sb);
        sb.append("));");

        sb.append(prefix).append(PARSE_DETAILS_ADDED + "=(");
        buildDiffKeys(setNewDiff, newFields, sb);
        sb.append("));");
 
        return sb.toString();
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
 
    /* (non-Javadoc)
     * @see com.yahoo.athenz.common.server.log.AuditLogMsgBuilder#parse(java.lang.String)
     */
    @Override
    public Struct parse(String logMsgBldrMsg) {
        // reverse what build() does, and pull out each component of the string
        CharSequence charSeq = logMsgBldrMsg.subSequence(0, logMsgBldrMsg.length());
        Struct msg = new Struct().with(PARSE_VERS, getMatchedGroup(PAT_VERS, 2, logMsgBldrMsg));
        msg.with(PARSE_WHEN, getMatchedGroup(PAT_WHEN, 2, charSeq)).
            with(PARSE_WHO, getMatchedGroup(PAT_WHO, 2, charSeq)).
            with(PARSE_WHY, getMatchedGroup(PAT_WHY, 2, charSeq)).
            with(PARSE_WHERE, getMatchedGroup(PAT_WHERE, 2, charSeq)).
            with(PARSE_CLIENT_IP, getMatchedGroup(PAT_CLTIP, 2, charSeq)).
            with(PARSE_WHAT_METH, getMatchedGroup(PAT_WHAT_METH, 2, charSeq)).
            with(PARSE_WHAT_API, getMatchedGroup(PAT_WHAT_API, 2, charSeq)).
            with(PARSE_WHAT_DOM, getMatchedGroup(PAT_WHAT_DOM, 2, charSeq)).
            with(PARSE_WHAT_ENT, getMatchedGroup(PAT_WHAT_ENT, 2, charSeq));
        
        // now get the WHAT-details
        int index = logMsgBldrMsg.indexOf(PARSE_WHAT_DETAILS + "=(");
        if (index != -1) {
            Struct details = new Struct();
            msg.with(PARSE_WHAT_DETAILS, details);

            String parseRemovedField = PARSE_DETAILS_REMOVED + "=(";
            String parseAddedField   = PARSE_DETAILS_ADDED   + "=(";

            // first level entities of WHAT-details are: CHANGED, REMOVED, ADDED
            //
            int removedIndex = logMsgBldrMsg.lastIndexOf(parseRemovedField);
            int addedIndex   = logMsgBldrMsg.indexOf(parseAddedField, removedIndex);
            if (removedIndex != -1) {
                int removedValIndex = removedIndex + parseRemovedField.length();
                int endOfRemIndex = addedIndex;
                if (addedIndex == -1) {
                    endOfRemIndex = logMsgBldrMsg.length();
                }
                endOfRemIndex  = logMsgBldrMsg.lastIndexOf(')', endOfRemIndex);
                String removed = logMsgBldrMsg.substring(removedValIndex, addedIndex);
                details.with(PARSE_DETAILS_REMOVED, removed);
            }
            
            if (addedIndex != -1) {
                String added = logMsgBldrMsg.substring(addedIndex + parseAddedField.length());
                details.with(PARSE_DETAILS_ADDED, added);
            }

            // process the CHANGED section - which can contain embedded Struct's
            //
            int changedIndex = logMsgBldrMsg.indexOf(PARSE_DETAILS_CHANGED + "=", index);
            if (changedIndex != -1) {
                int endingIndex = removedIndex != -1 ?
                    removedIndex : 
                    (addedIndex != -1 ? addedIndex : logMsgBldrMsg.length());
                String changed = logMsgBldrMsg.substring(changedIndex, endingIndex);
                details.with(PARSE_DETAILS_CHANGED, changed);

                // CHANGED can contain multiple ADDED-VALUES, REMOVED-VALUES, {FROM,TO} pairs
                // make lists for each of these and add to details

                Array addedValues = new Array();
                findChangedValues(addedValues, changed, PARSE_DETAILS_ADDEDVALS + "=(", "));", true);
                if (addedValues.size() > 0) {
                    details.with(PARSE_DETAILS_ADDEDVALS, addedValues);
                }

                Array removedValues = new Array();
                findChangedValues(removedValues, changed, PARSE_DETAILS_REMOVEDVALS + "=(", "));", true);
                if (removedValues.size() > 0) {
                    details.with(PARSE_DETAILS_REMOVEDVALS, removedValues);
                }

                // FROM/TO pairs
                Array fromToValues = new Array();
                findChangedValues(fromToValues, changed, PARSE_FROM + "=(", "));", true);
                if (fromToValues.size() > 0) {
                    details.with(PARSE_DETAILS_FROMTOVALS, fromToValues);
                }

                // look for embedded Struct - ADDED/REMOVED fields
                // if there are embedded Struct's in the original entity, then
                // due to recursion there can be multiple REMOVED and ADDED entries
                // puttenantroles is one of those ZMS api that can cause this
                Array removedFields = new Array();
                findChangedValues(removedFields, changed, parseRemovedField, "));", true);
                if (removedFields.size() > 0) {
                    details.with(PARSE_DETAILS_EMB_REMOVEDVALS, removedFields);
                }

                Array addedFields = new Array();
                findChangedValues(addedFields, changed, parseAddedField, "));", true);
                if (addedFields.size() > 0) {
                    details.with(PARSE_DETAILS_EMB_ADDEDVALS, addedFields);
                }
            }
        }
        return msg;
    }

    void findChangedValues(Array values, String changed, String fieldName, String endFieldStr, boolean wantPrefix) {
        int endOfArrayIndex = 0;
        for (int valIndex = changed.indexOf(fieldName, endOfArrayIndex);
             valIndex != -1;
             valIndex = changed.indexOf(fieldName, endOfArrayIndex)) {
                     
            endOfArrayIndex = changed.indexOf(endFieldStr, valIndex);
            if (endOfArrayIndex == -1) {
                break;
            }

            String value = "";
            if (wantPrefix && (valIndex - 3 > 0)) {
                // ex: ";org=(FROM=", "CHANGED=(modified=(FROM=("
                // go backwards from valIndex to either ';', or '('
                for (int cnt = valIndex - 2; cnt > -1; --cnt) {
                    char endChar = changed.charAt(cnt) ;
                    if (endChar == ';' || endChar == '(') {
                        valIndex = cnt + 1;
                        break;
                    }
                }
            }

            int addOffset = changed.length() > endOfArrayIndex ?  1 : 0;
            value = changed.substring(valIndex, endOfArrayIndex + addOffset);
            values.add(value);
        }
    }
    
    String getMatchedGroup(Pattern patty, int groupNum, CharSequence logMsg) {
        Matcher pm = patty.matcher(logMsg);
        if (pm.matches() && pm.groupCount() >= groupNum) {
            return pm.group(groupNum);
        }
        return null;
    }
    
    // Set the diff between the Arrays into the added set and/or the removed set StringBuilder.
    // If the Array elements are Struct, it will set them appropriately but not recur into them.
    //
    void buildDiffArray(Array origVal, Array newVal, StringBuilder addedSetSb, StringBuilder removedSetSb) {

        // create set for each Array of elements 
        //
        Set<String> origValSet = new HashSet<String>();
        Iterator<Object> elems = origVal.iterator();
        for (; elems != null && elems.hasNext(); ) {
            Object obj = elems.next();
            StringBuilder sb = new StringBuilder(SB_MIN_SIZE_INIT);
            Value.appendToString(obj, sb, null);
            origValSet.add(sb.toString());
        }

        Set<String> newValSet = new HashSet<String>();
        for (elems = newVal.iterator(); elems != null && elems.hasNext(); ) {
            Object obj = elems.next();
            StringBuilder sb = new StringBuilder(SB_MIN_SIZE_INIT);
            Value.appendToString(obj, sb, null);
            newValSet.add(sb.toString());
        }
        // HAVE: set of serialized elements for original and new set of elements

        // Build the diff sets now
        //
        Set<String> removedValSet = new HashSet<String>(origValSet);
        removedValSet.removeAll(newValSet); // gets a diff - contains Removed elements
        newValSet.removeAll(origValSet); // gets a diff - contains Added elements
        // HAVE: set of serialized elements for added and removed elements

        // print the set of removed elements
        buildDiffValueSet(removedValSet, removedSetSb);
        // print the set of added elements
        buildDiffValueSet(newValSet, addedSetSb);
    }

    // Set all the elements of the value Set into the StringBuilder
    //
    void buildDiffValueSet(Set<String> valSet, StringBuilder sb) {
        if (valSet.isEmpty()) {
            sb.append(NULL_STR);
            return;
        }
        for (Iterator<String> elems = valSet.iterator(); elems != null && elems.hasNext();) {
            sb.append(elems.next());
            if (elems.hasNext()) {
                sb.append(",");
            }
        }
    }
    
    // Set only the key/value pairs specified in the set of key names into the StringBuilder
    //
    void buildDiffKeys(Set<String> setDiffKeyNames, Struct dataStruct, StringBuilder sb) {
        
        if (setDiffKeyNames.isEmpty()) {
            sb.append(NULL_STR);
            return;
        }
        Iterator<String> it = setDiffKeyNames.iterator();
        while (it != null && it.hasNext()) {
            String key = it.next();
            sb.append(key + "=");
            Object val = dataStruct.get(key);
            if (val == null) {
                val = NULL_STR;
            }
            Value.appendToString(val, sb, null);
            if (it.hasNext()) {
                sb.append(",");
            }
        }
    }

}

