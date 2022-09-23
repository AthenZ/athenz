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

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.common.server.db.RolesProvider;
import com.yahoo.athenz.common.server.notification.NotificationManager;
import com.yahoo.athenz.common.server.notification.NotificationToEmailConverterCommon;
import com.yahoo.athenz.zts.ZTSClientNotification;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import static org.mockito.ArgumentMatchers.any;
import static org.testng.AssertJUnit.assertFalse;
import static org.testng.AssertJUnit.assertTrue;

public class ZTSClientNotificationSenderImplTest {
    private final NotificationToEmailConverterCommon notificationToEmailConverterCommon = new NotificationToEmailConverterCommon(null);

    @Test
    public void testInit() {
        ZTSClientNotificationSenderImpl ztsClientNotificationSender = new ZTSClientNotificationSenderImpl();
        NotificationManager notificationManager = Mockito.mock(NotificationManager.class);
        Mockito.when(notificationManager.getNotificationUserAuthority()).thenReturn(Mockito.mock(Authority.class));
        RolesProvider rolesProvider = Mockito.mock(RolesProvider.class);
        String serverName = "testServer";
        boolean initResult = ztsClientNotificationSender.init(notificationManager, rolesProvider, serverName);
        assertTrue(initResult);
        initResult = ztsClientNotificationSender.init(notificationManager, rolesProvider, null);
        assertFalse(initResult);
        initResult = ztsClientNotificationSender.init(notificationManager, null, serverName);
        assertFalse(initResult);
        initResult = ztsClientNotificationSender.init(null, rolesProvider, serverName);
        assertFalse(initResult);
    }

    @Test
    public void testSendNotificationInit() {
        ZTSClientNotificationSenderImpl ztsClientNotificationSender = new ZTSClientNotificationSenderImpl();
        NotificationManager notificationManager = Mockito.mock(NotificationManager.class);
        RolesProvider rolesProvider = Mockito.mock(RolesProvider.class);
        String serverName = "testServer";
        ztsClientNotificationSender.init(notificationManager, rolesProvider, serverName);

        ZTSClientNotification ztsClientNotification = Mockito.mock(ZTSClientNotification.class);
        ztsClientNotificationSender.sendNotification(ztsClientNotification);
        Mockito.verify(notificationManager, Mockito.times(1)).sendNotifications(any());
    }

    @Test
    public void testSendNotificationNotInit() {
        ZTSClientNotificationSenderImpl ztsClientNotificationSender = new ZTSClientNotificationSenderImpl();
        NotificationManager notificationManager = Mockito.mock(NotificationManager.class);
        ztsClientNotificationSender.init(notificationManager, null, null);

        ZTSClientNotification ztsClientNotification = Mockito.mock(ZTSClientNotification.class);
        ztsClientNotificationSender.sendNotification(ztsClientNotification);
        Mockito.verify(notificationManager, Mockito.times(0)).sendNotifications(any());
    }
}
