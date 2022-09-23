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
package com.yahoo.athenz.zms.config;

import com.yahoo.athenz.zms.Domain;
import com.yahoo.athenz.zms.Group;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.utils.ZMSUtils;

public class MemberDueDays {

    final long userDueDateMillis;
    final long serviceDueDateMillis;
    final long groupDueDateMillis;

    public enum Type {
        EXPIRY,
        REMINDER
    }

    public MemberDueDays(Domain domain, Role role, Type type) {

        Integer domainUserDays;
        Integer domainServiceDays;
        Integer domainGroupDays;
        Integer roleUserDays;
        Integer roleServiceDays;
        Integer roleGroupDays;

        // domain is null in the case of review reminder due dates but
        // for expiry we always have both domains and roles

        if (type == Type.EXPIRY) {
            domainUserDays = domain.getMemberExpiryDays();
            domainServiceDays = domain.getServiceExpiryDays();
            domainGroupDays = domain.getGroupExpiryDays();
            roleUserDays = role.getMemberExpiryDays();
            roleServiceDays = role.getServiceExpiryDays();
            roleGroupDays = role.getGroupExpiryDays();
        } else {
            domainUserDays = null;
            domainServiceDays = null;
            domainGroupDays = null;
            roleUserDays = role.getMemberReviewDays();
            roleServiceDays = role.getServiceReviewDays();
            roleGroupDays = role.getGroupReviewDays();
        }

        userDueDateMillis = ZMSUtils.configuredDueDateMillis(domainUserDays, roleUserDays);
        serviceDueDateMillis = ZMSUtils.configuredDueDateMillis(domainServiceDays, roleServiceDays);
        groupDueDateMillis = ZMSUtils.configuredDueDateMillis(domainGroupDays, roleGroupDays);
    }

    public MemberDueDays(Domain domain, Group group) {

        // for groups we only have user and service members
        // groups cannot include other groups

        Integer domainUserDays = domain.getMemberExpiryDays();
        Integer domainServiceDays = domain.getServiceExpiryDays();
        Integer groupUserDays = group.getMemberExpiryDays();
        Integer groupServiceDays = group.getServiceExpiryDays();

        userDueDateMillis = ZMSUtils.configuredDueDateMillis(domainUserDays, groupUserDays);
        serviceDueDateMillis = ZMSUtils.configuredDueDateMillis(domainServiceDays, groupServiceDays);
        groupDueDateMillis = 0;
    }

    public long getUserDueDateMillis() {
        return userDueDateMillis;
    }

    public long getServiceDueDateMillis() {
        return serviceDueDateMillis;
    }

    public long getGroupDueDateMillis() {
        return groupDueDateMillis;
    }
}
