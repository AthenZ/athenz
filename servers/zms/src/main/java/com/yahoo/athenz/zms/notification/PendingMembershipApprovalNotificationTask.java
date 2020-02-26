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

import com.yahoo.athenz.common.server.notification.Notification;
import com.yahoo.athenz.common.server.notification.NotificationCommon;
import com.yahoo.athenz.common.server.notification.NotificationTask;
import com.yahoo.athenz.zms.DBService;
import com.yahoo.athenz.zms.ZMSConsts;

import java.util.Collections;
import java.util.List;
import java.util.Set;

import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.NOTIFICATION_TYPE_MEMBERSHIP_APPROVAL_REMINDER;

public class PendingMembershipApprovalNotificationTask implements NotificationTask {

    private final DBService dbService;
    private final int pendingRoleMemberLifespan;
    private final String monitorIdentity;
    private NotificationCommon notificationCommon;
    private final static String DESCRIPTION = "pending membership approvals reminders";

    public PendingMembershipApprovalNotificationTask(DBService dbService, int pendingRoleMemberLifespan, String monitorIdentity, String userDomainPrefix) {
        this.dbService = dbService;
        this.pendingRoleMemberLifespan = pendingRoleMemberLifespan;
        this.monitorIdentity = monitorIdentity;
        ZMSDomainRoleMembersFetcher zmsDomainRoleMembersFetcher = new ZMSDomainRoleMembersFetcher(dbService, ZMSConsts.USER_DOMAIN_PREFIX);
        this.notificationCommon = new NotificationCommon(zmsDomainRoleMembersFetcher, userDomainPrefix);
    }

    @Override
    public List<Notification> getNotifications() {
        dbService.processExpiredPendingMembers(pendingRoleMemberLifespan, monitorIdentity);
        Set<String> recipients = dbService.getPendingMembershipApproverRoles();
        return Collections.singletonList(notificationCommon.createNotification(NOTIFICATION_TYPE_MEMBERSHIP_APPROVAL_REMINDER, recipients, null));
    }

    @Override
    public String getDescription() {
        return DESCRIPTION;
    }
}
