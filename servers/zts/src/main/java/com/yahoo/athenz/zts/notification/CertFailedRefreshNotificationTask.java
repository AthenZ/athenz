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

package com.yahoo.athenz.zts.notification;

import com.yahoo.athenz.auth.util.AthenzUtils;
import com.yahoo.athenz.auth.util.GlobStringsMatcher;
import com.yahoo.athenz.common.server.cert.X509CertRecord;
import com.yahoo.athenz.common.server.dns.HostnameResolver;
import com.yahoo.athenz.common.server.notification.*;
import com.yahoo.athenz.common.server.util.ResourceUtils;
import com.yahoo.athenz.zms.DomainData;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.cert.InstanceCertManager;
import com.yahoo.athenz.zts.store.DataStore;
import com.yahoo.rdl.Timestamp;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.MessageFormat;
import java.util.*;
import java.util.stream.Collectors;

import static com.yahoo.athenz.common.ServerCommonConsts.ADMIN_ROLE_NAME;
import static com.yahoo.athenz.common.ServerCommonConsts.USER_DOMAIN_PREFIX;
import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.*;
import static com.yahoo.athenz.common.server.notification.impl.MetricNotificationService.*;
import static com.yahoo.athenz.zts.ZTSConsts.ZTS_PROP_ATHENZ_GUIDE;

public class CertFailedRefreshNotificationTask implements NotificationTask {
    private final String serverName;
    private final List<String> providers;
    private final InstanceCertManager instanceCertManager;
    private final NotificationCommon notificationCommon;
    private final DataStore dataStore;
    private static final Logger LOGGER = LoggerFactory.getLogger(CertFailedRefreshNotificationTask.class);
    private final static String DESCRIPTION = "certificate failed refresh notification";
    private final HostnameResolver hostnameResolver;
    private final CertFailedRefreshNotificationToEmailConverter certFailedRefreshNotificationToEmailConverter;
    private final CertFailedRefreshNotificationToMetricConverter certFailedRefreshNotificationToMetricConverter;
    private final GlobStringsMatcher globStringsMatcher;

    private final static String SNOOZED_DOMAIN_TAG_KEY = "zts.DisableCertRefreshNotifications";
    private final static String SNOOZED_DOMAIN_TAG_VALUE = "true";

    public CertFailedRefreshNotificationTask(InstanceCertManager instanceCertManager,
                                             DataStore dataStore,
                                             HostnameResolver hostnameResolver,
                                             String userDomainPrefix,
                                             String serverName,
                                             int httpsPort,
                                             NotificationToEmailConverterCommon notificationToEmailConverterCommon) {
        this.serverName = serverName;
        this.providers = getProvidersList();
        this.instanceCertManager = instanceCertManager;
        this.dataStore = dataStore;
        DomainRoleMembersFetcher domainRoleMembersFetcher = new DomainRoleMembersFetcher(dataStore, USER_DOMAIN_PREFIX);
        this.notificationCommon = new NotificationCommon(domainRoleMembersFetcher, userDomainPrefix);
        this.hostnameResolver = hostnameResolver;
        final String apiHostName = System.getProperty(ZTSConsts.ZTS_PROP_NOTIFICATION_API_HOSTNAME, serverName);
        this.certFailedRefreshNotificationToEmailConverter = new CertFailedRefreshNotificationToEmailConverter(apiHostName, httpsPort, notificationToEmailConverterCommon);
        this.certFailedRefreshNotificationToMetricConverter = new CertFailedRefreshNotificationToMetricConverter();
        globStringsMatcher = new GlobStringsMatcher(ZTSConsts.ZTS_PROP_NOTIFICATION_CERT_FAIL_IGNORED_SERVICES_LIST);
    }

    private List<String> getProvidersList() {
        return AthenzUtils.splitCommaSeparatedSystemProperty(ZTSConsts.ZTS_PROP_NOTIFICATION_CERT_FAIL_PROVIDER_LIST);
    }

    @Override
    public List<Notification> getNotifications() {
        if (providers == null || providers.isEmpty()) {
            LOGGER.warn("No configured providers. Notifications will not be sent.");
            return new ArrayList<>();
        }

        List<X509CertRecord> unrefreshedCerts = new ArrayList<>();
        for (String provider : providers) {
            unrefreshedCerts.addAll(instanceCertManager.getUnrefreshedCertsNotifications(serverName, provider));
        }
        if (unrefreshedCerts.isEmpty()) {
            LOGGER.info("No unrefreshed certificates available to send notifications");
            return new ArrayList<>();
        }

        List<X509CertRecord> unrefreshedCertsValidServices = getRecordsWithValidServices(unrefreshedCerts);
        if (unrefreshedCertsValidServices.isEmpty()) {
            LOGGER.info("No unrefreshed certificates with configured services available to send notifications");
            return new ArrayList<>();
        }

        List<X509CertRecord> unrefreshedCertsUnsnoozed = getRecordsNotSnoozed(unrefreshedCertsValidServices);
        if (unrefreshedCertsUnsnoozed.isEmpty()) {
            LOGGER.info("No unrefreshed certificates in un-snoozed domains");
            return new ArrayList<>();
        }

        List<X509CertRecord> unrefreshedCertsValidHosts = getRecordsWithValidHosts(unrefreshedCertsUnsnoozed);
        if (unrefreshedCertsValidHosts.isEmpty()) {
            LOGGER.info("No unrefreshed certificates with valid hosts available to send notifications");
            return new ArrayList<>();
        } else {
            LOGGER.info("Number of valid certificate records that will receive notifications: {}", unrefreshedCertsValidHosts.size());
        }

        Map<String, List<X509CertRecord>> domainToCertRecordsMap = getDomainToCertRecordsMap(unrefreshedCertsValidHosts);

        return generateNotificationsForAdmins(domainToCertRecordsMap);
    }

    private List<X509CertRecord> getRecordsWithValidServices(List<X509CertRecord> unrefreshedCerts) {
        return unrefreshedCerts.stream()
                .filter(record -> !globStringsMatcher.isMatch(record.getService()))
                .collect(Collectors.toList());
    }

    private List<X509CertRecord> getRecordsNotSnoozed(List<X509CertRecord> unrefreshedCerts) {
        List<X509CertRecord> unsnoozedDomains = new ArrayList<>();
        for (X509CertRecord x509CertRecord : unrefreshedCerts) {
            String domainName = AthenzUtils.extractPrincipalDomainName(x509CertRecord.getService());
            DomainData domainData = dataStore.getDomainData(domainName);
            if (!isDomainSnoozed(domainData)) {
                unsnoozedDomains.add(x509CertRecord);
            }
        }

        return unsnoozedDomains;
    }

    private boolean isDomainSnoozed(DomainData domainData) {
        if (domainData == null || domainData.getTags() == null || domainData.getTags().get(SNOOZED_DOMAIN_TAG_KEY) == null || domainData.getTags().get(SNOOZED_DOMAIN_TAG_KEY).getList() == null) {
            return false;
        }

        List<String> snoozeTagValues = domainData.getTags().get(SNOOZED_DOMAIN_TAG_KEY).getList();
        return snoozeTagValues.stream().anyMatch(value -> value.equalsIgnoreCase(SNOOZED_DOMAIN_TAG_VALUE));
    }

    private List<Notification> generateNotificationsForAdmins(Map<String, List<X509CertRecord>> domainToCertRecordsMap) {
        List<Notification> notificationList = new ArrayList<>();
        domainToCertRecordsMap.forEach((domain, records) -> {
            Map<String, String> details = getNotificationDetails(domain, records);
            Notification notification = notificationCommon.createNotification(
                    ResourceUtils.roleResourceName(domain, ADMIN_ROLE_NAME),
                    details,
                    certFailedRefreshNotificationToEmailConverter,
                    certFailedRefreshNotificationToMetricConverter);
            if (notification != null) {
                notificationList.add(notification);
            }
        });

        return notificationList;
    }

    private List<X509CertRecord> getRecordsWithValidHosts(List<X509CertRecord> unrefreshedCerts) {
        unrefreshedCerts.stream()
                .filter(record -> StringUtil.isEmpty(record.getHostName()))
                .peek(record -> LOGGER.warn("Record with empty hostName: {}", record))
                .collect(Collectors.toList());

        // Filter all records with non existing hosts or hosts not recognized by DNS
        return unrefreshedCerts.stream()
                    .filter(record -> !StringUtil.isEmpty(record.getHostName()) && (hostnameResolver == null || hostnameResolver.isValidHostname(record.getHostName())))
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
            String hostName = certRecord.getHostName();
            certDetails.append(AthenzUtils.extractPrincipalServiceName(certRecord.getService())).append(';')
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
        return (date != null) ? Timestamp.fromMillis(date.getTime()).toString() : "";
    }

    @Override
    public String getDescription() {
        return DESCRIPTION;
    }

    public static class CertFailedRefreshNotificationToEmailConverter implements NotificationToEmailConverter {
        private static final String EMAIL_TEMPLATE_UNREFRESHED_CERTS = "messages/unrefreshed-certs.html";
        private static final String UNREFRESHED_CERTS_SUBJECT = "athenz.notification.email.unrefreshed.certs.subject";
        private static final String DEFAULT_ATHENZ_GUIDE = "https://athenz.github.io/athenz/";

        private final NotificationToEmailConverterCommon notificationToEmailConverterCommon;
        private final String emailUnrefreshedCertsBody;
        private final String serverName;
        private final int httpsPort;
        private final String athenzGuide;

        public CertFailedRefreshNotificationToEmailConverter(final String serverName, int httpsPort, NotificationToEmailConverterCommon notificationToEmailConverterCommon) {
            this.notificationToEmailConverterCommon = notificationToEmailConverterCommon;
            emailUnrefreshedCertsBody = notificationToEmailConverterCommon.readContentFromFile(getClass().getClassLoader(), EMAIL_TEMPLATE_UNREFRESHED_CERTS);
            this.serverName = serverName;
            this.httpsPort = httpsPort;
            athenzGuide = System.getProperty(ZTS_PROP_ATHENZ_GUIDE, DEFAULT_ATHENZ_GUIDE);
        }

        private String getUnrefreshedCertsBody(Map<String, String> metaDetails) {
            if (metaDetails == null) {
                return null;
            }

            String bodyWithDeleteEndpoint = addInstanceDeleteEndpointDetails(metaDetails, emailUnrefreshedCertsBody);
            return notificationToEmailConverterCommon.generateBodyFromTemplate(
                    metaDetails,
                    bodyWithDeleteEndpoint,
                    NOTIFICATION_DETAILS_DOMAIN,
                    NOTIFICATION_DETAILS_UNREFRESHED_CERTS,
                    6, null);
        }

        private String addInstanceDeleteEndpointDetails(Map<String, String> metaDetails, String messageWithoutZtsDeleteEndpoint) {
            String ztsApiAddress = serverName + ":" + httpsPort;
            String domainPlaceHolder = metaDetails.get(NOTIFICATION_DETAILS_DOMAIN);
            String providerPlaceHolder = "&lt;PROVIDER&gt;";
            String servicePlaceHolder = "&lt;SERVICE&gt;";
            String instanceIdHolder = "&lt;INSTANCE-ID&gt;";

            long numberOfRecords = metaDetails.get(NOTIFICATION_DETAILS_UNREFRESHED_CERTS)
                    .chars()
                    .filter(ch -> ch == '|')
                    .count() + 1;

            // If there is only one record, fill the real values to make it easier for him
            if (numberOfRecords == 1) {
                String[] recordDetails = metaDetails.get(NOTIFICATION_DETAILS_UNREFRESHED_CERTS).split(";");
                servicePlaceHolder = recordDetails[0];
                providerPlaceHolder = recordDetails[1];
                instanceIdHolder = recordDetails[2];
            }

            return MessageFormat.format(messageWithoutZtsDeleteEndpoint,
                    "{0}", "{1}", "{2}", "{3}", // Skip template arguments that will be filled later
                    ztsApiAddress,
                    providerPlaceHolder,
                    domainPlaceHolder,
                    servicePlaceHolder,
                    instanceIdHolder,
                    athenzGuide);
        }

        @Override
        public NotificationEmail getNotificationAsEmail(Notification notification) {
            String subject = notificationToEmailConverterCommon.getSubject(UNREFRESHED_CERTS_SUBJECT);
            String body = getUnrefreshedCertsBody(notification.getDetails());
            Set<String> fullyQualifiedEmailAddresses = notificationToEmailConverterCommon.getFullyQualifiedEmailAddresses(notification.getRecipients());
            return new NotificationEmail(subject, body, fullyQualifiedEmailAddresses);
        }
    }

    public static class CertFailedRefreshNotificationToMetricConverter implements NotificationToMetricConverter {

        private final static String NOTIFICATION_TYPE = "cert_fail_refresh";
        private final NotificationToMetricConverterCommon notificationToMetricConverterCommon = new NotificationToMetricConverterCommon();

        @Override
        public NotificationMetric getNotificationAsMetrics(Notification notification, Timestamp currentTime) {
            Map<String, String> details = notification.getDetails();
            String domain = details.get(NOTIFICATION_DETAILS_DOMAIN);
            List<String[]> attributes = new ArrayList<>();
            String[] records = details.get(NOTIFICATION_DETAILS_UNREFRESHED_CERTS).split("\\|");
            String currentTimeStr = currentTime.toString();
            for (String record: records) {
                String[] recordAttributes = record.split(";");

                String[] metricRecord = new String[]{
                        METRIC_NOTIFICATION_TYPE_KEY, NOTIFICATION_TYPE,
                        METRIC_NOTIFICATION_DOMAIN_KEY, domain,
                        METRIC_NOTIFICATION_SERVICE_KEY, recordAttributes[0],
                        METRIC_NOTIFICATION_PROVIDER_KEY, recordAttributes[1],
                        METRIC_NOTIFICATION_INSTANCE_ID_KEY, recordAttributes[2],
                        METRIC_NOTIFICATION_UPDATE_DAYS_KEY, notificationToMetricConverterCommon.getNumberOfDaysBetweenTimestamps(currentTimeStr, recordAttributes[3]),
                        METRIC_NOTIFICATION_EXPIRY_DAYS_KEY, notificationToMetricConverterCommon.getNumberOfDaysBetweenTimestamps(currentTimeStr, recordAttributes[4])
                };

                attributes.add(metricRecord);
            }

            return new NotificationMetric(attributes);
        }
    }
}
