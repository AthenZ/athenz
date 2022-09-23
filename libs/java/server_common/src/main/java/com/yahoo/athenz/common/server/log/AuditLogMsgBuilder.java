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
package com.yahoo.athenz.common.server.log;

public interface AuditLogMsgBuilder {

    /**
     * A unique identifier
     * @param UUID message UUID value
     * @return this
     */
    AuditLogMsgBuilder uuId(String UUID);
    
    String uuId();

    /**
     * Return a tag with the version of the msg builder used to build the message.
     * Ex:  "VERS(athenz-2.1);"
     * @return version tag all ready to set in a log message
     */
    String versionTag();
    
    /**
     * Full name of who made the authorization change
     * @param whoVal should be just the full name of the Principal
     * @return this
     */
    AuditLogMsgBuilder whoFullName(String whoVal);

    String whoFullName();
    
    /**
     * who made the authorization change
     * @param whoVal typically contains a token (user, role)
     *        The calling client/user requesting the change.
     * @return this
     */
    AuditLogMsgBuilder who(String whoVal);

    String who();

    /**
     * why was this change requested - justification via SOX ticket number
     * @param whyVal typically a ticket number or some identifier for reference
     *        The SOX ticket number.
     * @return this
     */
    AuditLogMsgBuilder why(String whyVal);

    String why();

    AuditLogMsgBuilder when(String whenVal);

    String when();

    /**
     * IP address of requesting client
     * @param clientIpAddr address of the calling client
     *        The IP address of the calling client(who).
     * @return this
     */
    AuditLogMsgBuilder clientIp(String clientIpAddr);

    String clientIp();

    /**
     * This is where the change request was received - server endpoint.
     * @param whereVal is the server hostname where the request was received
     * @return this
     */
    AuditLogMsgBuilder where(String whereVal);

    String where();

    /**
     * The REST methods required to be reported are PUT, POST, DELETE.
     * @param whatMethodVal is the typical REST method
     *        This is the REST method, ie. "PUT" or "POST", etc
     * @return this
     */
    AuditLogMsgBuilder whatMethod(String whatMethodVal);

    String whatMethod();

    /**
     * The publicly exported API receiving the change request.
     * @param whatApiVal names the API that received the request
     *        This is the server public method serving the request, ex: "putRole"
     * @return this
     */
    AuditLogMsgBuilder whatApi(String whatApiVal);

    String whatApi();

    /**
     * Name of the domain that is affected by the change.
     * @param whatDomainVal is the name of the domain being affected
     *        This is the Athenz domain being changed, ex: "xobni"
     * @return this
     */
    AuditLogMsgBuilder whatDomain(String whatDomainVal);

    String whatDomain();

    /**
     * Name of the entity being changed. An entity is a policy, role, service, et al.
     * @param whatEntityVal is the name of the particular entity
     *        This is the entity in the Athenz domain being changed.
     *        So for example, if the role called "admin" is changed, then entity is "admin".
     * @return this
     */
    AuditLogMsgBuilder whatEntity(String whatEntityVal);

    String whatEntity();

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
    AuditLogMsgBuilder whatDetails(String whatDetailsVal);

    String whatDetails();

    /**
     * Call this to build the string representation of the data fields set herein.
     * @return String representation of the message to be logged
     */
    String build();
}
