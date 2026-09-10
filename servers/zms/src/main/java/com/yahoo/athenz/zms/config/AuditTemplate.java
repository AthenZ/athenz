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
import com.yahoo.athenz.zms.DomainMeta;
import com.yahoo.athenz.zms.Group;
import com.yahoo.athenz.zms.GroupMeta;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.RoleMeta;

import java.util.Objects;

/**
 * The audit template specifies the maximum expiry and review settings that
 * must be enforced on any domain, role or group that is audit enabled. The
 * template is loaded from a json file during server startup and contains
 * three sections - domain, role and group. Only the member/service/group
 * expiry and review day settings from each section are honored. A missing
 * or 0 value in the template indicates that there is no limit for that
 * setting.
 */
public class AuditTemplate {

    private DomainMeta domain;
    private RoleMeta role;
    private GroupMeta group;

    public DomainMeta getDomain() {
        return domain;
    }

    public void setDomain(DomainMeta domain) {
        this.domain = domain;
    }

    public RoleMeta getRole() {
        return role;
    }

    public void setRole(RoleMeta role) {
        this.role = role;
    }

    public GroupMeta getGroup() {
        return group;
    }

    public void setGroup(GroupMeta group) {
        this.group = group;
    }

    /**
     * Verify that none of the configured expiry/review settings
     * are negative values.
     * @throws IllegalArgumentException if any value is negative
     */
    public void validate() {
        if (domain != null) {
            validateValue("domain.memberExpiryDays", domain.getMemberExpiryDays());
            validateValue("domain.serviceExpiryDays", domain.getServiceExpiryDays());
            validateValue("domain.groupExpiryDays", domain.getGroupExpiryDays());
        }
        if (role != null) {
            validateValue("role.memberExpiryDays", role.getMemberExpiryDays());
            validateValue("role.serviceExpiryDays", role.getServiceExpiryDays());
            validateValue("role.groupExpiryDays", role.getGroupExpiryDays());
            validateValue("role.memberReviewDays", role.getMemberReviewDays());
            validateValue("role.serviceReviewDays", role.getServiceReviewDays());
            validateValue("role.groupReviewDays", role.getGroupReviewDays());
        }
        if (group != null) {
            validateValue("group.memberExpiryDays", group.getMemberExpiryDays());
            validateValue("group.serviceExpiryDays", group.getServiceExpiryDays());
        }
    }

    static void validateValue(final String name, Integer value) {
        if (value != null && value < 0) {
            throw new IllegalArgumentException("Invalid audit template value for " + name + ": " + value);
        }
    }

    /**
     * Return the value that must be set on the object given the configured
     * limit. If there is no limit configured (null or 0) then the object
     * value is returned unchanged. Otherwise, if the object value is not
     * set, is 0 (no expiry) or is bigger than the limit, then the limit
     * is returned.
     * @param limit value configured in the audit template
     * @param value current value of the object
     * @return value to be set on the object
     */
    public static Integer applyLimit(Integer limit, Integer value) {
        if (limit == null || limit <= 0) {
            return value;
        }
        if (value == null || value <= 0 || value > limit) {
            return limit;
        }
        return value;
    }

    /**
     * Return the value that must be set on the meta object given the
     * configured limit. The meta object semantics are that a null value
     * indicates that the current value of the object must not be changed,
     * so the limit is applied against the effective value (meta value if
     * specified, otherwise the current object value). If the limit does
     * not need to be imposed then the meta value is returned unchanged.
     * @param limit value configured in the audit template
     * @param metaValue value specified in the meta object (null - no change)
     * @param currentValue current value of the object
     * @return value to be set on the meta object
     */
    public static Integer applyMetaLimit(Integer limit, Integer metaValue, Integer currentValue) {
        Integer effectiveValue = metaValue != null ? metaValue : currentValue;
        Integer limitedValue = applyLimit(limit, effectiveValue);
        return Objects.equals(limitedValue, effectiveValue) ? metaValue : limitedValue;
    }

    public void applyDomainSettings(Domain obj) {
        if (domain == null) {
            return;
        }
        obj.setMemberExpiryDays(applyLimit(domain.getMemberExpiryDays(), obj.getMemberExpiryDays()));
        obj.setServiceExpiryDays(applyLimit(domain.getServiceExpiryDays(), obj.getServiceExpiryDays()));
        obj.setGroupExpiryDays(applyLimit(domain.getGroupExpiryDays(), obj.getGroupExpiryDays()));
    }

    public void applyDomainMetaSettings(DomainMeta meta, Domain obj) {
        if (domain == null) {
            return;
        }
        meta.setMemberExpiryDays(applyMetaLimit(domain.getMemberExpiryDays(),
                meta.getMemberExpiryDays(), obj.getMemberExpiryDays()));
        meta.setServiceExpiryDays(applyMetaLimit(domain.getServiceExpiryDays(),
                meta.getServiceExpiryDays(), obj.getServiceExpiryDays()));
        meta.setGroupExpiryDays(applyMetaLimit(domain.getGroupExpiryDays(),
                meta.getGroupExpiryDays(), obj.getGroupExpiryDays()));
    }

    public void applyRoleSettings(Role obj) {
        if (role == null) {
            return;
        }
        obj.setMemberExpiryDays(applyLimit(role.getMemberExpiryDays(), obj.getMemberExpiryDays()));
        obj.setServiceExpiryDays(applyLimit(role.getServiceExpiryDays(), obj.getServiceExpiryDays()));
        obj.setGroupExpiryDays(applyLimit(role.getGroupExpiryDays(), obj.getGroupExpiryDays()));
        obj.setMemberReviewDays(applyLimit(role.getMemberReviewDays(), obj.getMemberReviewDays()));
        obj.setServiceReviewDays(applyLimit(role.getServiceReviewDays(), obj.getServiceReviewDays()));
        obj.setGroupReviewDays(applyLimit(role.getGroupReviewDays(), obj.getGroupReviewDays()));
    }

    public void applyRoleMetaSettings(RoleMeta meta, Role obj) {
        if (role == null) {
            return;
        }
        meta.setMemberExpiryDays(applyMetaLimit(role.getMemberExpiryDays(),
                meta.getMemberExpiryDays(), obj.getMemberExpiryDays()));
        meta.setServiceExpiryDays(applyMetaLimit(role.getServiceExpiryDays(),
                meta.getServiceExpiryDays(), obj.getServiceExpiryDays()));
        meta.setGroupExpiryDays(applyMetaLimit(role.getGroupExpiryDays(),
                meta.getGroupExpiryDays(), obj.getGroupExpiryDays()));
        meta.setMemberReviewDays(applyMetaLimit(role.getMemberReviewDays(),
                meta.getMemberReviewDays(), obj.getMemberReviewDays()));
        meta.setServiceReviewDays(applyMetaLimit(role.getServiceReviewDays(),
                meta.getServiceReviewDays(), obj.getServiceReviewDays()));
        meta.setGroupReviewDays(applyMetaLimit(role.getGroupReviewDays(),
                meta.getGroupReviewDays(), obj.getGroupReviewDays()));
    }

    public void applyGroupSettings(Group obj) {
        if (group == null) {
            return;
        }
        obj.setMemberExpiryDays(applyLimit(group.getMemberExpiryDays(), obj.getMemberExpiryDays()));
        obj.setServiceExpiryDays(applyLimit(group.getServiceExpiryDays(), obj.getServiceExpiryDays()));
    }

    public void applyGroupMetaSettings(GroupMeta meta, Group obj) {
        if (group == null) {
            return;
        }
        meta.setMemberExpiryDays(applyMetaLimit(group.getMemberExpiryDays(),
                meta.getMemberExpiryDays(), obj.getMemberExpiryDays()));
        meta.setServiceExpiryDays(applyMetaLimit(group.getServiceExpiryDays(),
                meta.getServiceExpiryDays(), obj.getServiceExpiryDays()));
    }
}
