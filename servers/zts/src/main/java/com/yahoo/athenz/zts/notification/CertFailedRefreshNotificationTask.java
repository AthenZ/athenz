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

package com.yahoo.athenz.zts.notification;

import com.yahoo.athenz.common.server.notification.Notification;
import com.yahoo.athenz.common.server.notification.NotificationCommon;
import com.yahoo.athenz.common.server.notification.NotificationTask;
import com.yahoo.athenz.zts.cert.InstanceCertManager;
import com.yahoo.athenz.zts.store.DataStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

import static com.yahoo.athenz.common.ServerCommonConsts.USER_DOMAIN_PREFIX;

public class CertFailedRefreshNotificationTask implements NotificationTask {
    private final String serverName;
    private final InstanceCertManager instanceCertManager;
    private final DataStore dataStore;
    private final NotificationCommon notificationCommon;
    private static final Logger LOGGER = LoggerFactory.getLogger(CertFailedRefreshNotificationTask.class);
    private final static String DESCRIPTION = "certificate failed refresh notification";

    public CertFailedRefreshNotificationTask(InstanceCertManager instanceCertManager, DataStore dataStore, String userDomainPrefix, String serverName) {
        this.serverName = serverName;
        this.instanceCertManager = instanceCertManager;
        this.dataStore = dataStore;
        ZTSDomainRoleMembersFetcher ztsDomainRoleMembersFetcher = new ZTSDomainRoleMembersFetcher(dataStore, USER_DOMAIN_PREFIX);
        this.notificationCommon = new NotificationCommon(ztsDomainRoleMembersFetcher, userDomainPrefix);
    }

    @Override
    public List<Notification> getNotifications() {
        return new ArrayList<>();
        // TODO: Uncomment and continue implementation when UnrefreshedNotification email template is ready

/*        List<Notification> notificationList = new ArrayList<>();
        List<X509CertRecord> unrefreshedRecords = instanceCertManager.getUnrefreshedNotifications(serverName);
        if (unrefreshedRecords == null || unrefreshedRecords.isEmpty()) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("No unrefreshed certificates available to send notifications");
            }
            return notificationList;
        }


        for (X509CertRecord x509CertRecord: unrefreshedRecords) {
            String domainName = AthenzUtils.extractPrincipalDomainName(x509CertRecord.getService());
            DomainData domainData = dataStore.getDomainData(domainName);

        }*/
    }

    @Override
    public String getDescription() {
        return DESCRIPTION;
    }
}
