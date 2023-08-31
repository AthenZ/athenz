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

import com.yahoo.athenz.common.server.notification.NotificationTask;
import com.yahoo.athenz.common.server.notification.NotificationTaskFactory;
import com.yahoo.athenz.common.server.notification.NotificationToEmailConverterCommon;
import com.yahoo.athenz.zms.DBService;
import com.yahoo.athenz.zms.ZMSConsts;

import java.util.ArrayList;
import java.util.List;

public class ZMSNotificationTaskFactory implements NotificationTaskFactory {

    private final DBService dbService;
    private final String userDomainPrefix;
    private final NotificationToEmailConverterCommon notificationToEmailConverterCommon;

    public ZMSNotificationTaskFactory(DBService dbService, String userDomainPrefix,
            NotificationToEmailConverterCommon notificationToEmailConverterCommon) {

        this.dbService = dbService;
        this.userDomainPrefix = userDomainPrefix;
        this.notificationToEmailConverterCommon = notificationToEmailConverterCommon;
    }

    @Override
    public List<NotificationTask> getNotificationTasks() {

        List<NotificationTask> notificationTasks = new ArrayList<>();
        int pendingRoleMemberLifespan = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_PENDING_ROLE_MEMBER_LIFESPAN,
                ZMSConsts.ZMS_PENDING_ROLE_MEMBER_LIFESPAN_DEFAULT));
        final String monitorIdentity = System.getProperty(ZMSConsts.ZMS_PROP_MONITOR_IDENTITY, ZMSConsts.SYS_AUTH_MONITOR);
        boolean consolidateNotifications = Boolean.parseBoolean(System.getProperty(
                ZMSConsts.ZMS_PROP_CONSOLIDATE_NOTIFICATIONS, "false"));

        notificationTasks.add(new PendingRoleMembershipApprovalNotificationTask(dbService, pendingRoleMemberLifespan,
                monitorIdentity, userDomainPrefix, notificationToEmailConverterCommon));
        notificationTasks.add(new PendingGroupMembershipApprovalNotificationTask(dbService, pendingRoleMemberLifespan,
                monitorIdentity, userDomainPrefix, notificationToEmailConverterCommon));
        notificationTasks.add(new RoleMemberExpiryNotificationTask(dbService, userDomainPrefix,
                notificationToEmailConverterCommon, consolidateNotifications));
        notificationTasks.add(new RoleMemberReviewNotificationTask(dbService, userDomainPrefix,
                notificationToEmailConverterCommon, consolidateNotifications));
        notificationTasks.add(new GroupMemberExpiryNotificationTask(dbService, userDomainPrefix,
                notificationToEmailConverterCommon, consolidateNotifications));
        return notificationTasks;
    }
}
