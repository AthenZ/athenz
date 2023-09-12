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

package com.yahoo.athenz.zts.notification;

import com.yahoo.athenz.common.server.db.RolesProvider;
import com.yahoo.athenz.common.server.notification.Notification;
import com.yahoo.athenz.common.server.notification.NotificationManager;
import com.yahoo.athenz.common.server.notification.NotificationToEmailConverterCommon;
import com.yahoo.athenz.zts.ZTSClientNotification;
import com.yahoo.athenz.zts.ZTSClientNotificationSender;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import static com.yahoo.athenz.common.ServerCommonConsts.USER_DOMAIN_PREFIX;

public class ZTSClientNotificationSenderImpl implements ZTSClientNotificationSender {
    private static final Logger LOGGER = LoggerFactory.getLogger(ZTSClientNotificationSenderImpl.class);

    private NotificationManager notificationManager;
    private RolesProvider rolesProvider;
    private String serverName;
    private boolean isInit = false;
    private NotificationToEmailConverterCommon notificationToEmailConverterCommon;

    public boolean init(NotificationManager notificationManager, RolesProvider rolesProvider, String serverName) {
        this.isInit = false;
        this.notificationManager = notificationManager;
        this.rolesProvider = rolesProvider;
        this.serverName = serverName;
        if (this.notificationManager != null) {
            this.notificationToEmailConverterCommon = new NotificationToEmailConverterCommon(notificationManager.getNotificationUserAuthority());
        }
        if (this.notificationManager != null && this.rolesProvider != null && !StringUtil.isEmpty(this.serverName)) {
            this.isInit = true;
        } else {
            LOGGER.warn("ZTSClientNotificationSenderImpl must be initiated with all arguments before it can be used");
        }

        return this.isInit;
    }

    @Override
    public void sendNotification(ZTSClientNotification ztsClientNotification) {
        if (isInit) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Sending AWSZTSHealthNotificationTask notification");
            }
            List<Notification> notifications = new AWSZTSHealthNotificationTask(ztsClientNotification, rolesProvider, USER_DOMAIN_PREFIX, serverName, notificationToEmailConverterCommon).getNotifications();
            notificationManager.sendNotifications(notifications);
        } else {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("NotificationSender isn't initialized. Will not send notification");
            }
        }
    }
}
