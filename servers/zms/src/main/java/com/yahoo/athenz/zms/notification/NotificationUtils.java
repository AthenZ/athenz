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

package com.yahoo.athenz.zms.notification;

import com.google.common.base.Splitter;
import com.yahoo.athenz.auth.AuthorityConsts;
import com.yahoo.athenz.common.server.notification.DomainRoleMembersFetcher;
import com.yahoo.athenz.common.server.notification.Notification;
import com.yahoo.athenz.common.server.notification.NotificationMetric;
import com.yahoo.athenz.common.server.notification.NotificationToMetricConverterCommon;
import com.yahoo.athenz.common.server.util.ResourceUtils;
import com.yahoo.athenz.zms.ZMSConsts;
import com.yahoo.rdl.Timestamp;
import org.eclipse.jetty.util.StringUtil;

import java.util.*;
import java.util.concurrent.TimeUnit;

import static com.yahoo.athenz.common.server.notification.impl.MetricNotificationService.*;

public class NotificationUtils {

    // we're going to use 8 days max for our week expiry disable check
    public static final long WEEK_EXPIRY_CHECK = TimeUnit.MILLISECONDS.convert(8, TimeUnit.DAYS);

    public static NotificationMetric getNotificationAsMetrics(Notification notification, Timestamp currentTime,
            final String notificationType, final String keyName, final String objectType, final String timeType,
            NotificationToMetricConverterCommon notificationToMetricConverterCommon) {

        Map<String, String> details = notification.getDetails();
        List<String[]> attributes = new ArrayList<>();
        String[] records = details.get(keyName).split("\\|");
        for (String record: records) {

            // the notification records contains 4 elements:
            // <domain>;<role|group>;<principal>;<expiry|review>

            String[] recordAttributes = record.split(";");
            if (recordAttributes.length != 4) {
                // Bad entry, skip
                continue;
            }

            String[] metricRecord = new String[] {
                    METRIC_NOTIFICATION_TYPE_KEY, notificationType,
                    METRIC_NOTIFICATION_DOMAIN_KEY, recordAttributes[0],
                    objectType, recordAttributes[1],
                    METRIC_NOTIFICATION_MEMBER_KEY, recordAttributes[2],
                    timeType, notificationToMetricConverterCommon.getNumberOfDaysBetweenTimestamps(currentTime.toString(), recordAttributes[3])
            };

            attributes.add(metricRecord);
        }

        return new NotificationMetric(attributes);
    }

    public static Set<String> extractNotifyRoleMembers(final DomainRoleMembersFetcher domainRoleMembersFetcher,
            final String domainName, final String notifyRoles) {

        Iterable<String> roleNames = Splitter.on(',')
                .omitEmptyStrings()
                .trimResults()
                .split(notifyRoles);

        Set<String> roleAdminMembers = new HashSet<>();
        for (String roleName : roleNames) {
            int idx = roleName.indexOf(AuthorityConsts.ROLE_SEP);
            if (idx != -1) {
                roleAdminMembers.addAll(domainRoleMembersFetcher.getDomainRoleMembers(
                        roleName.substring(0, idx), roleName.substring(idx + AuthorityConsts.ROLE_SEP.length())));
            } else {
                roleAdminMembers.addAll(domainRoleMembersFetcher.getDomainRoleMembers(domainName, roleName));
            }
        }
        return roleAdminMembers;
    }

    public static Set<String> getRecipientRoles(Boolean auditEnabled, final String domainName, final String auditOrgName,
            final String notifyRoles) {

        Set<String> recipients = new HashSet<>();
        if (auditEnabled == Boolean.TRUE) {

            recipients.add(ResourceUtils.roleResourceName(ZMSConsts.SYS_AUTH_AUDIT_BY_DOMAIN, domainName));
            recipients.add(ResourceUtils.roleResourceName(ZMSConsts.SYS_AUTH_AUDIT_BY_ORG, auditOrgName));

        } else {

            // if we're given a notify role list then we're going
            // to add those role members to the recipient list
            // otherwise use the admin role for the domain

            if (StringUtil.isEmpty(notifyRoles)) {
                recipients.add(ResourceUtils.roleResourceName(domainName, ZMSConsts.ADMIN_ROLE_NAME));
            } else {
                Iterable<String> roleNames = Splitter.on(',')
                        .omitEmptyStrings()
                        .trimResults()
                        .split(notifyRoles);

                for (String roleName : roleNames) {
                    if (!roleName.contains(AuthorityConsts.ROLE_SEP)) {
                        recipients.add(ResourceUtils.roleResourceName(domainName, roleName));
                    } else {
                        recipients.add(roleName);
                    }
                }
            }
        }
        return recipients;
    }

    public static Set<String> getRecipientRolesByDomain(Boolean auditEnabled, final String domainName, final String auditOrgName,
                                                final String notifyRoles, DomainRoleMembersFetcher domainRoleMembersFetcher) {

        Set<String> recipients = new HashSet<>();
        if (auditEnabled == Boolean.TRUE) {

            recipients.add(ResourceUtils.roleResourceName(ZMSConsts.SYS_AUTH_AUDIT_BY_DOMAIN, domainName));
            recipients.add(ResourceUtils.roleResourceName(ZMSConsts.SYS_AUTH_AUDIT_BY_ORG, auditOrgName));

        } else {

            // if we're given a notify role list then we're going
            // to add those role members to the recipient list
            // otherwise use the domain name

            if (StringUtil.isEmpty(notifyRoles)) {
                recipients.add(domainName);
            } else {
                recipients.addAll(NotificationUtils.extractNotifyRoleMembers(domainRoleMembersFetcher,
                        domainName, notifyRoles));
            }
        }
        return recipients;
    }
}
