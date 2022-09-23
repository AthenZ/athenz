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

import com.yahoo.athenz.common.server.dns.HostnameResolver;
import com.yahoo.athenz.common.server.notification.NotificationTask;
import com.yahoo.athenz.common.server.notification.NotificationTaskFactory;
import com.yahoo.athenz.common.server.notification.NotificationToEmailConverterCommon;
import com.yahoo.athenz.zts.cert.InstanceCertManager;
import com.yahoo.athenz.zts.store.DataStore;

import java.util.Collections;
import java.util.List;

public class ZTSNotificationTaskFactory implements NotificationTaskFactory {
    private final InstanceCertManager instanceCertManager;
    private final DataStore dataStore;
    private final HostnameResolver hostnameResolver;
    private final String userDomainPrefix;
    private final String serverName;
    private final int httpsPort;
    private final NotificationToEmailConverterCommon notificationToEmailConverterCommon;

    public ZTSNotificationTaskFactory(InstanceCertManager instanceCertManager,
                                      DataStore dataStore,
                                      HostnameResolver hostnameResolver,
                                      String userDomainPrefix,
                                      String serverName,
                                      int httpsPort,
                                      NotificationToEmailConverterCommon notificationToEmailConverterCommon) {
        this.httpsPort = httpsPort;
        this.instanceCertManager = instanceCertManager;
        this.dataStore = dataStore;
        this.hostnameResolver = hostnameResolver;
        this.userDomainPrefix = userDomainPrefix;
        this.serverName = serverName;
        this.notificationToEmailConverterCommon = notificationToEmailConverterCommon;
    }

    @Override
    public List<NotificationTask> getNotificationTasks() {
        return Collections.singletonList(new CertFailedRefreshNotificationTask(
                instanceCertManager,
                dataStore,
                hostnameResolver,
                userDomainPrefix,
                serverName,
                httpsPort,
                notificationToEmailConverterCommon));
    }
}
