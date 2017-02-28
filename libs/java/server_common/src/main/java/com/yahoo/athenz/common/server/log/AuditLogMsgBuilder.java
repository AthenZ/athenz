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

public interface AuditLogMsgBuilder {

    /**
     * Return a tag with the version of the msg builder used to build the message.
     * Ex:  "VERS(athenz-2.1);"
     * @return version tag all ready to set in a log message
     */
    public String versionTag();
    
    /**
     * who made the authorization change
     * @param whoVal typically contains a token (user, role)
     *        The calling client/user requesting the change.
     * @return this
     */
    public AuditLogMsgBuilder who(String whoVal);

    public String who();

    /**
     * why was this change requested - justification via SOX ticket number
     * @param whyVal typically a ticket number or some identifier for reference
     *        The SOX ticket number.
     * @return this
     */
    public AuditLogMsgBuilder why(String whyVal);

    public String why();

    public AuditLogMsgBuilder when(String whenVal);

    public String when();

    /**
     * IP address of requesting client
     * @param clientIpAddr address of the calling client
     *        The IP address of the calling client(who).
     * @return this
     */
    public AuditLogMsgBuilder clientIp(String clientIpAddr);

    public String clientIp();

    /**
     * This is where the change request was received - server endpoint.
     * @param whereVal is the server address where the request was received
     *        The IP address and ports of the server where it receives the
     *        requests at.
     *        Ex: '{"server-ip":"198.177.62.9","server-https-port":"4453","server-http-port":"10080"}'
     * @return this
     */
    public AuditLogMsgBuilder whereIp(String whereVal);

    public AuditLogMsgBuilder whereHttpsPort(String whereVal);

    public AuditLogMsgBuilder whereHttpPort(String whereVal);

    // Ex: '{"server-ip":"198.177.62.9","server-https-port":"4453","server-http-port":"10080"}'
    public String where();

    /**
     * The REST methods required to be reported are PUT, POST, DELETE.
     * @param whatMethodVal is the typical REST method
     *        This is the REST method, ie. "PUT" or "POST", etc
     * @return this
     */
    public AuditLogMsgBuilder whatMethod(String whatMethodVal);

    public String whatMethod();

    /**
     * The publicly exported API receiving the change request.
     * @param whatApiVal names the API that received the request
     *        This is the server public method serving the request, ex: "putRole"
     * @return this
     */
    public AuditLogMsgBuilder whatApi(String whatApiVal);

    public String whatApi();

    /**
     * Name of the domain that is affected by the change.
     * @param whatDomainVal is the name of the domain being affected
     *        This is the Athenz domain being changed, ex: "xobni"
     * @return this
     */
    public AuditLogMsgBuilder whatDomain(String whatDomainVal);

    public String whatDomain();

    /**
     * Name of the entity being changed. An entity is a policy, role, service, et al.
     * @param whatEntityVal is the name of the particular entity
     *        This is the entity in the Athenz domain being changed.
     *        So for example, if the role called "admin" is changed, then entity is "admin".
     * @return this
     */
    public AuditLogMsgBuilder whatEntity(String whatEntityVal);

    public String whatEntity();

    /**
     * @param whatDetailsVal specific details of the changes
     *        The caller will specify the entity(whatEntity) that was 
     *        changed. If the entity is a role, and members were added, then
     *        the details will specify that members were added.
     *        Ex: '{"members-removed":["user.manning"],"members-added"=["user.brady"]}'
     *        See the whatDetails() helper that takes Set's. It can be used with
     *        method to sort out the changes to enhance the details message.
     *        Usage can be:
     *        Builder bldr = bldr.whatDetails("members-changed");
     *        bldr         = bldr.whatDetails(oldAttrSet, newAttrSet);
     * @return this
     */
    public AuditLogMsgBuilder whatDetails(String whatDetailsVal);

    public String whatDetails();

    /**
     * Call this to build the string representation of the data fields set herein.
     * @return String representation of the message to be logged
     */
    public String build();
}
