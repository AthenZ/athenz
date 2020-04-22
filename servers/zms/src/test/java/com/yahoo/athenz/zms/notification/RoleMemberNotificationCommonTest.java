/*
 *  Copyright 2020 Verizon Media
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

import com.yahoo.athenz.common.server.notification.NotificationToEmailConverter;
import com.yahoo.athenz.zms.DBService;
import com.yahoo.athenz.zms.DomainRoleMember;
import com.yahoo.athenz.zms.MemberRole;
import com.yahoo.rdl.Timestamp;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.util.*;

import static com.yahoo.athenz.common.ServerCommonConsts.USER_DOMAIN_PREFIX;
import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.*;
import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertTrue;

public class RoleMemberNotificationCommonTest {
    @Test
    public void testProcessRoleReminder() {
        DBService dbsvc = Mockito.mock(DBService.class);
        RoleMemberNotificationCommon roleMemberNotificationCommon = new RoleMemberNotificationCommon(dbsvc, USER_DOMAIN_PREFIX);

        NotificationToEmailConverter[] notificationConverters = {
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(),
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToEmailConverter()
        };

        for (NotificationToEmailConverter notificationConverter : notificationConverters) {
            Map<String, List<MemberRole>> domainAdminMap = new HashMap<>();
            DomainRoleMember roleMember = new DomainRoleMember();
            roleMember.setMemberName("user.joe");
            Map<String, String> details = roleMemberNotificationCommon.processRoleReminder(domainAdminMap, roleMember, notificationConverter);
            assertTrue(details.isEmpty());

            domainAdminMap.clear();
            roleMember.setMemberRoles(Collections.emptyList());
            details = roleMemberNotificationCommon.processRoleReminder(domainAdminMap, roleMember, notificationConverter);
            assertTrue(details.isEmpty());

            final Timestamp expirationTs = Timestamp.fromMillis(100);
            final Timestamp reviewTs = Timestamp.fromMillis(50);
            final Timestamp expectedTs = (notificationConverter.getClass().equals(
                    RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter.class)) ?
                    expirationTs : reviewTs;

            domainAdminMap.clear();

            List<MemberRole> memberRoles = new ArrayList<>();
            memberRoles.add(new MemberRole().setRoleName("role1").setDomainName("athenz1").setMemberName("user.joe")
                    .setExpiration(expirationTs).setReviewReminder(reviewTs));
            roleMember.setMemberRoles(memberRoles);

            domainAdminMap.clear();
            details = roleMemberNotificationCommon.processRoleReminder(domainAdminMap, roleMember, notificationConverter);
            assertEquals(details.size(), 2);
            assertEquals(details.get(NOTIFICATION_DETAILS_EXPIRY_ROLES),
                    "athenz1;role1;" + expectedTs);
            assertEquals(details.get(NOTIFICATION_DETAILS_MEMBER), "user.joe");

            assertEquals(domainAdminMap.size(), 1);
            List<MemberRole> domainRoleMembers = domainAdminMap.get("athenz1");
            assertEquals(domainRoleMembers.size(), 1);
            assertEquals(domainRoleMembers.get(0).getMemberName(), "user.joe");

            memberRoles.add(new MemberRole().setRoleName("role1").setDomainName("athenz2").setMemberName("user.joe")
                    .setExpiration(expirationTs).setReviewReminder(reviewTs));
            memberRoles.add(new MemberRole().setRoleName("role2").setDomainName("athenz2").setMemberName("user.joe")
                    .setExpiration(expirationTs).setReviewReminder(reviewTs));
            domainAdminMap.clear();
            details = roleMemberNotificationCommon.processRoleReminder(domainAdminMap, roleMember, notificationConverter);
            assertEquals(details.size(), 2);
            assertEquals(details.get(NOTIFICATION_DETAILS_EXPIRY_ROLES),
                    "athenz1;role1;" + expectedTs + "|athenz2;role1;" + expectedTs + "|athenz2;role2;" + expectedTs);
            assertEquals(details.get(NOTIFICATION_DETAILS_MEMBER), "user.joe");
            assertEquals(domainAdminMap.size(), 2);
            domainRoleMembers = domainAdminMap.get("athenz1");
            assertEquals(domainRoleMembers.size(), 1);
            assertEquals(domainRoleMembers.get(0).getMemberName(), "user.joe");
            domainRoleMembers = domainAdminMap.get("athenz2");
            assertEquals(domainRoleMembers.size(), 2);
            assertEquals(domainRoleMembers.get(0).getMemberName(), "user.joe");
            assertEquals(domainRoleMembers.get(1).getMemberName(), "user.joe");
        }
    }

    @Test
    public void testProcessMemberReminderEmptySet() {
        DBService dbsvc = Mockito.mock(DBService.class);

        RoleMemberNotificationCommon roleMemberNotificationCommon = new RoleMemberNotificationCommon(dbsvc, USER_DOMAIN_PREFIX);

        NotificationToEmailConverter[] notificationConverters = {
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToEmailConverter()
        };

        for (NotificationToEmailConverter notificationConverter : notificationConverters) {
            Map<String, String> details = roleMemberNotificationCommon.processMemberReminder("athenz", null, notificationConverter);
            assertTrue(details.isEmpty());

            details = roleMemberNotificationCommon.processMemberReminder("athenz", Collections.emptyList(), notificationConverter);
            assertTrue(details.isEmpty());

            final Timestamp expirationTs = Timestamp.fromMillis(100);
            final Timestamp reviewTs = Timestamp.fromMillis(50);
            final Timestamp expectedTs = (notificationConverter.getClass().equals(
                    RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter.class))
                    ? expirationTs : reviewTs;
            List<MemberRole> memberRoles = new ArrayList<>();
            memberRoles.add(new MemberRole().setRoleName("role1").setDomainName("athenz").setMemberName("user.joe")
                    .setExpiration(expirationTs).setReviewReminder(reviewTs));

            details = roleMemberNotificationCommon.processMemberReminder("athenz", memberRoles, notificationConverter);
            assertEquals(details.size(), 2);
            assertEquals(details.get(NOTIFICATION_DETAILS_EXPIRY_MEMBERS),
                    "user.joe;role1;" + expectedTs.toString());
            assertEquals(details.get(NOTIFICATION_DETAILS_DOMAIN), "athenz");

            memberRoles.add(new MemberRole().setRoleName("role1").setDomainName("athenz").setMemberName("user.jane")
                    .setExpiration(expirationTs).setReviewReminder(reviewTs));
            details = roleMemberNotificationCommon.processMemberReminder("athenz", memberRoles, notificationConverter);
            assertEquals(details.size(), 2);
            assertEquals(details.get(NOTIFICATION_DETAILS_EXPIRY_MEMBERS),
                    "user.joe;role1;" + expectedTs.toString() + "|user.jane;role1;" + expectedTs.toString());
            assertEquals(details.get(NOTIFICATION_DETAILS_DOMAIN), "athenz");
        }
    }
}
