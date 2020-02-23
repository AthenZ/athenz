/*
 * Copyright 2020 Verizon Media
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

package com.yahoo.athenz.zms.notification;

import com.google.common.base.Splitter;
import com.yahoo.athenz.common.server.notification.DomainRoleMembersFetcher;
import com.yahoo.athenz.common.server.notification.Notification;
import com.yahoo.athenz.common.server.notification.NotificationCommon;
import com.yahoo.athenz.common.server.notification.NotificationTask;
import com.yahoo.athenz.zms.DBService;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.ZMSConsts;
import com.yahoo.athenz.zms.utils.ZMSUtils;

import java.util.*;

import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.NOTIFICATION_TYPE_MEMBERSHIP_APPROVAL;

public class PutMembershipNotificationTask implements NotificationTask {
    final String domain;
    final String org;
    final Role role;
    private Map<String, String> details;
    private NotificationCommon notificationCommon;
    private final static String DESCRIPTION = "Membership Approval Notification";

    public PutMembershipNotificationTask(String domain, String org, Role role, Map<String, String> details, DBService dbService, String userDomainPrefix) {
        this.domain = domain;
        this.org = org;
        this.role = role;
        this.details = details;
        DomainRoleMembersFetcher domainRoleMembersFetcher = new ZMSDomainRoleMembersFetcher(dbService, userDomainPrefix);
        this.notificationCommon = new NotificationCommon(domainRoleMembersFetcher, userDomainPrefix);
    }

    @Override
    public List<Notification> getNotifications() {
        // we need to generate the appropriate recipients for the notification
        // there are 2 possible use cases we need to handle here:
        // a) audit enabled role - we need to add the domain and org roles
        //          from the sys.auth.audit domain
        // b) review/self-serve roles - we need to look at the configured
        //          role list for notification and if not present then default
        //          to the admin role from the domain

        Set<String> recipients = new HashSet<>();
        if (role.getAuditEnabled() == Boolean.TRUE) {

            recipients.add(ZMSUtils.roleResourceName(ZMSConsts.SYS_AUTH_AUDIT_BY_DOMAIN, domain));
            recipients.add(ZMSUtils.roleResourceName(ZMSConsts.SYS_AUTH_AUDIT_BY_ORG, org));

        } else {

            // if we're given a notify role list then we're going
            // to add those role members to the recipient list
            // otherwise use the admin role for the domain

            final String notifyRoles = role.getNotifyRoles();
            if (notifyRoles == null || notifyRoles.isEmpty()) {
                recipients.add(ZMSUtils.roleResourceName(domain, ZMSConsts.ADMIN_ROLE_NAME));
            } else {
                Iterable<String> roleNames = Splitter.on(',')
                        .omitEmptyStrings()
                        .trimResults()
                        .split(notifyRoles);

                for (String roleName : roleNames) {
                    if (roleName.indexOf(":role.") == -1) {
                        recipients.add(ZMSUtils.roleResourceName(domain, roleName));
                    } else {
                        recipients.add(roleName);
                    }
                }
            }
        }

        // create and process our notification

        return Collections.singletonList(notificationCommon.createNotification(NOTIFICATION_TYPE_MEMBERSHIP_APPROVAL,
                recipients, details));
    }

    @Override
    public String getDescription() {
        return DESCRIPTION;
    }
}
