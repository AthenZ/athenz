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

import com.yahoo.athenz.auth.util.AthenzUtils;
import com.yahoo.athenz.common.server.cert.X509CertRecord;
import com.yahoo.athenz.common.server.dns.HostnameResolver;
import com.yahoo.athenz.common.server.notification.*;
import com.yahoo.athenz.common.server.util.ResourceUtils;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.cert.InstanceCertManager;
import com.yahoo.athenz.zts.store.DataStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Timestamp;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.yahoo.athenz.common.ServerCommonConsts.ADMIN_ROLE_NAME;
import static com.yahoo.athenz.common.ServerCommonConsts.USER_DOMAIN_PREFIX;
import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.*;

public class CertFailedRefreshNotificationTask implements NotificationTask {
    private final String serverName;
    private final List<String> providers;
    private final InstanceCertManager instanceCertManager;
    private final NotificationCommon notificationCommon;
    private static final Logger LOGGER = LoggerFactory.getLogger(CertFailedRefreshNotificationTask.class);
    private final static String DESCRIPTION = "certificate failed refresh notification";
    private final HostnameResolver hostnameResolver;
    private final CertFailedRefreshNotificationToEmailConverter certFailedRefreshNotificationToEmailConverter;

    public CertFailedRefreshNotificationTask(InstanceCertManager instanceCertManager,
                                             DataStore dataStore,
                                             HostnameResolver hostnameResolver,
                                             String userDomainPrefix,
                                             String serverName) {
        this.serverName = serverName;
        this.providers = getProvidersList();
        this.instanceCertManager = instanceCertManager;
        ZTSDomainRoleMembersFetcher ztsDomainRoleMembersFetcher = new ZTSDomainRoleMembersFetcher(dataStore, USER_DOMAIN_PREFIX);
        this.notificationCommon = new NotificationCommon(ztsDomainRoleMembersFetcher, userDomainPrefix);
        this.hostnameResolver = hostnameResolver;
        this.certFailedRefreshNotificationToEmailConverter = new CertFailedRefreshNotificationToEmailConverter();
    }

    private List<String> getProvidersList() {
        String providersListStr = System.getProperty(ZTSConsts.ZTS_PROP_NOTIFICATION_CERT_FAIL_PROVIDER_LIST, null);

        if (providersListStr == null) {
            return new ArrayList<>();
        }

        return Stream.of(providersListStr.trim().split("\\s*,\\s*")).collect(Collectors.toList());
    }

    @Override
    public List<Notification> getNotifications() {
        if (providers == null || providers.isEmpty()) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("No configured providers");
            }
            return new ArrayList<>();
        }

        List<X509CertRecord> unrefreshedCerts = new ArrayList<>();
        for (String provider : providers) {
            unrefreshedCerts.addAll(instanceCertManager.getUnrefreshedCertsNotifications(serverName, provider));
        }
        if (unrefreshedCerts.isEmpty()) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("No unrefreshed certificates available to send notifications");
            }
            return new ArrayList<>();
        }

        List<X509CertRecord> unrefreshedCertsValidHosts = getRecordsWithValidHosts(unrefreshedCerts);
        Map<String, List<X509CertRecord>> domainToCertRecordsMap = getDomainToCertRecordsMap(unrefreshedCertsValidHosts);

        return generateNotificationsForAdmins(domainToCertRecordsMap);
    }

    private List<Notification> generateNotificationsForAdmins(Map<String, List<X509CertRecord>> domainToCertRecordsMap) {
        List<Notification> notificationList = new ArrayList<>();
        domainToCertRecordsMap.forEach((domain, records) -> {
            Map<String, String> details = getNotificationDetails(domain, records);
            Notification notification = notificationCommon.createNotification(
                    ResourceUtils.roleResourceName(domain, ADMIN_ROLE_NAME),
                    details,
                    certFailedRefreshNotificationToEmailConverter);
            if (notification != null) {
                notificationList.add(notification);
            }
        });

        return notificationList;
    }

    private List<X509CertRecord> getRecordsWithValidHosts(List<X509CertRecord> unrefreshedCerts) {
        return unrefreshedCerts.stream()
                    .filter(record -> hostnameResolver.isValidHostname(record.getHostName()))
                    .collect(Collectors.toList());
    }

    private Map<String, String> getNotificationDetails(String domainName, List<X509CertRecord> certRecords) {
        Map<String, String> details = new HashMap<>();

        // each domain can have multiple certificates that failed to refresh.
        // we're going to collect them into one
        // string and separate with | between those. The format will be:
        // certificateRecords := <certificate-entry>[|<certificate-entry]*
        // certificate-entry := <Service Name>;<Provider>;<InstanceID>;<Last refresh time>;<Expiration time>;<Hostname>;

        StringBuilder certDetails = new StringBuilder(256);
        for (X509CertRecord certRecord : certRecords) {
            if (certDetails.length() != 0) {
                certDetails.append('|');
            }

            String expiryTime =  getTimestampAsString(certRecord.getExpiryTime());
            String hostName = (certRecord.getHostName() != null) ? certRecord.getHostName() : "";
            certDetails.append(
                    certRecord.getService()).append(';')
                    .append(certRecord.getProvider()).append(';')
                    .append(certRecord.getInstanceId()).append(';')
                    .append(getTimestampAsString(certRecord.getCurrentTime())).append(';')
                    .append(expiryTime).append(';')
                    .append(hostName);
        }
        details.put(NOTIFICATION_DETAILS_UNREFRESHED_CERTS, certDetails.toString());
        details.put(NOTIFICATION_DETAILS_DOMAIN, domainName);
        return details;
    }


    private Map<String, List<X509CertRecord>> getDomainToCertRecordsMap(List<X509CertRecord> unrefreshedRecords) {
        Map<String, List<X509CertRecord>> domainToCertRecords = new HashMap<>();
        for (X509CertRecord x509CertRecord: unrefreshedRecords) {
            String domainName = AthenzUtils.extractPrincipalDomainName(x509CertRecord.getService());
            LOGGER.info("processing domain={}, hostName={}", domainName, x509CertRecord.getHostName());
            domainToCertRecords.putIfAbsent(domainName, new ArrayList<>());
            domainToCertRecords.get(domainName).add(x509CertRecord);
        }
        return domainToCertRecords;
    }

    private String getTimestampAsString(Date date) {
        return (date != null) ? new Timestamp(date.getTime()).toString() : "";
    }

    @Override
    public String getDescription() {
        return DESCRIPTION;
    }

    public static class CertFailedRefreshNotificationToEmailConverter implements NotificationToEmailConverter {
        private static final String EMAIL_TEMPLATE_UNREFRESHED_CERTS = "messages/unrefreshed-certs.html";
        private static final String UNREFRESHED_CERTS_SUBJECT = "athenz.notification.email.unrefreshed.certs.subject";
        private static final String UNREFRESHED_CERTS_BODY_ENTRY = "athenz.notification.email.unrefreshed.certs.body.entry";

        private final NotificationToEmailConverterCommon notificationToEmailConverterCommon;
        private String emailUnrefreshedCertsBody;

        public CertFailedRefreshNotificationToEmailConverter() {
            notificationToEmailConverterCommon = new NotificationToEmailConverterCommon();
            emailUnrefreshedCertsBody = notificationToEmailConverterCommon.readContentFromFile(getClass().getClassLoader(), EMAIL_TEMPLATE_UNREFRESHED_CERTS);
        }

        private String getUnrefreshedCertsBody(Map<String, String> metaDetails) {
            if (metaDetails == null) {
                return null;
            }

            return notificationToEmailConverterCommon.generateBodyFromTemplate(
                    metaDetails,
                    emailUnrefreshedCertsBody,
                    NOTIFICATION_DETAILS_DOMAIN,
                    NOTIFICATION_DETAILS_UNREFRESHED_CERTS,
                    6,
                    UNREFRESHED_CERTS_BODY_ENTRY);
        }

        @Override
        public NotificationEmail getNotificationAsEmail(Notification notification) {
            String subject = notificationToEmailConverterCommon.getSubject(UNREFRESHED_CERTS_SUBJECT);
            String body = getUnrefreshedCertsBody(notification.getDetails());
            Set<String> fullyQualifiedEmailAddresses = notificationToEmailConverterCommon.getFullyQualifiedEmailAddresses(notification.getRecipients());
            return new NotificationEmail(subject, body, fullyQualifiedEmailAddresses);
        }
    }
}
