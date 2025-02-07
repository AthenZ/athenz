/*
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.zms.notification;

import com.yahoo.athenz.auth.AuthorityConsts;
import com.yahoo.athenz.auth.util.AthenzUtils;
import com.yahoo.athenz.common.server.notification.DomainRoleMembersFetcher;
import com.yahoo.athenz.zms.DBService;
import com.yahoo.athenz.zms.Group;
import org.apache.commons.lang3.StringUtils;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static com.yahoo.athenz.common.ServerCommonConsts.ADMIN_ROLE_NAME;

public class MembershipDecisionNotificationCommon {
    private static final Logger LOGGER = LoggerFactory.getLogger(MembershipDecisionNotificationCommon.class);
    private final DBService dbService;
    private final DomainRoleMembersFetcher domainRoleMembersFetcher;
    private final String userDomainPrefix;

    MembershipDecisionNotificationCommon(DBService dbService, DomainRoleMembersFetcher domainRoleMembersFetcher, String userDomainPrefix) {
        this.dbService = dbService;
        this.domainRoleMembersFetcher = domainRoleMembersFetcher;
        this.userDomainPrefix = userDomainPrefix;
    }

    public Set<String> getRecipients(List<String> members) {
        Set<String> notifyMembers = new HashSet<>();
        for (String memberName : members) {
            if (StringUtils.isEmpty(memberName)) {
                continue;
            }
            int idx = memberName.indexOf(AuthorityConsts.GROUP_SEP);
            if (idx != -1) {
                final String domainName = memberName.substring(0, idx);
                final String groupName = memberName.substring(idx + AuthorityConsts.GROUP_SEP.length());
                Group group = dbService.getGroup(domainName, groupName, Boolean.FALSE, Boolean.FALSE);
                if (group == null) {
                    LOGGER.error("unable to retrieve group: {} in domain: {}", groupName, domainName);
                    continue;
                }
                if (!StringUtil.isEmpty(group.getNotifyRoles())) {
                    notifyMembers.addAll(NotificationUtils.extractNotifyRoleMembers(domainRoleMembersFetcher,
                            domainName, group.getNotifyRoles()));
                } else {
                    notifyMembers.addAll(domainRoleMembersFetcher.getDomainRoleMembers(domainName, ADMIN_ROLE_NAME));
                }
            } else {
                final String domainName = AthenzUtils.extractPrincipalDomainName(memberName);
                if (userDomainPrefix.equals(domainName + ".")) {
                    notifyMembers.add(memberName);
                } else {
                    // domain role fetcher only returns the human users
                    notifyMembers.addAll(domainRoleMembersFetcher.getDomainRoleMembers(domainName, ADMIN_ROLE_NAME));
                }
            }
        }
        return notifyMembers;
    }

    public Set<String> getRecipientsByDomain(List<String> members) {
        Set<String> notifyMembers = new HashSet<>();
        for (String memberName : members) {
            if (StringUtils.isEmpty(memberName)) {
                continue;
            }
            int idx = memberName.indexOf(AuthorityConsts.GROUP_SEP);
            if (idx != -1) {
                final String domainName = memberName.substring(0, idx);
                final String groupName = memberName.substring(idx + AuthorityConsts.GROUP_SEP.length());
                Group group = dbService.getGroup(domainName, groupName, Boolean.FALSE, Boolean.FALSE);
                if (group == null) {
                    LOGGER.error("unable to retrieve group: {} in domain: {}", groupName, domainName);
                    continue;
                }
                if (!StringUtil.isEmpty(group.getNotifyRoles())) {
                    notifyMembers.addAll(NotificationUtils.extractNotifyRoleMembers(domainRoleMembersFetcher,
                            domainName, group.getNotifyRoles()));
                } else {
                    notifyMembers.add(domainName);
                }
            } else {
                final String domainName = AthenzUtils.extractPrincipalDomainName(memberName);
                if (userDomainPrefix.equals(domainName + ".")) {
                    notifyMembers.add(memberName);
                } else {
                    notifyMembers.add(domainName);
                }
            }
        }
        return notifyMembers;
    }
}
