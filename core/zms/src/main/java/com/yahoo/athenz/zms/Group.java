//
// This file generated by rdl 1.5.2. Do not modify!
//

package com.yahoo.athenz.zms;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.List;
import java.util.Map;
import com.yahoo.rdl.*;

//
// Group - The representation for a Group with set of members.
//
@JsonIgnoreProperties(ignoreUnknown = true)
public class Group {
    @RdlOptional
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public Boolean selfServe;
    @RdlOptional
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public Boolean reviewEnabled;
    @RdlOptional
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public String notifyRoles;
    @RdlOptional
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public String userAuthorityFilter;
    @RdlOptional
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public String userAuthorityExpiration;
    @RdlOptional
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public Integer memberExpiryDays;
    @RdlOptional
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public Integer serviceExpiryDays;
    @RdlOptional
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public Map<String, TagValueList> tags;
    @RdlOptional
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public Boolean auditEnabled;
    @RdlOptional
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public Boolean deleteProtection;
    @RdlOptional
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public Timestamp lastReviewedDate;
    @RdlOptional
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public Boolean selfRenew;
    @RdlOptional
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public Integer selfRenewMins;
    @RdlOptional
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public Integer maxMembers;
    @RdlOptional
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public ResourceGroupOwnership resourceOwnership;
    @RdlOptional
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public String principalDomainFilter;
    @RdlOptional
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public String notifyDetails;
    public String name;
    @RdlOptional
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public Timestamp modified;
    @RdlOptional
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public List<GroupMember> groupMembers;
    @RdlOptional
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public List<GroupAuditLog> auditLog;

    public Group setSelfServe(Boolean selfServe) {
        this.selfServe = selfServe;
        return this;
    }
    public Boolean getSelfServe() {
        return selfServe;
    }
    public Group setReviewEnabled(Boolean reviewEnabled) {
        this.reviewEnabled = reviewEnabled;
        return this;
    }
    public Boolean getReviewEnabled() {
        return reviewEnabled;
    }
    public Group setNotifyRoles(String notifyRoles) {
        this.notifyRoles = notifyRoles;
        return this;
    }
    public String getNotifyRoles() {
        return notifyRoles;
    }
    public Group setUserAuthorityFilter(String userAuthorityFilter) {
        this.userAuthorityFilter = userAuthorityFilter;
        return this;
    }
    public String getUserAuthorityFilter() {
        return userAuthorityFilter;
    }
    public Group setUserAuthorityExpiration(String userAuthorityExpiration) {
        this.userAuthorityExpiration = userAuthorityExpiration;
        return this;
    }
    public String getUserAuthorityExpiration() {
        return userAuthorityExpiration;
    }
    public Group setMemberExpiryDays(Integer memberExpiryDays) {
        this.memberExpiryDays = memberExpiryDays;
        return this;
    }
    public Integer getMemberExpiryDays() {
        return memberExpiryDays;
    }
    public Group setServiceExpiryDays(Integer serviceExpiryDays) {
        this.serviceExpiryDays = serviceExpiryDays;
        return this;
    }
    public Integer getServiceExpiryDays() {
        return serviceExpiryDays;
    }
    public Group setTags(Map<String, TagValueList> tags) {
        this.tags = tags;
        return this;
    }
    public Map<String, TagValueList> getTags() {
        return tags;
    }
    public Group setAuditEnabled(Boolean auditEnabled) {
        this.auditEnabled = auditEnabled;
        return this;
    }
    public Boolean getAuditEnabled() {
        return auditEnabled;
    }
    public Group setDeleteProtection(Boolean deleteProtection) {
        this.deleteProtection = deleteProtection;
        return this;
    }
    public Boolean getDeleteProtection() {
        return deleteProtection;
    }
    public Group setLastReviewedDate(Timestamp lastReviewedDate) {
        this.lastReviewedDate = lastReviewedDate;
        return this;
    }
    public Timestamp getLastReviewedDate() {
        return lastReviewedDate;
    }
    public Group setSelfRenew(Boolean selfRenew) {
        this.selfRenew = selfRenew;
        return this;
    }
    public Boolean getSelfRenew() {
        return selfRenew;
    }
    public Group setSelfRenewMins(Integer selfRenewMins) {
        this.selfRenewMins = selfRenewMins;
        return this;
    }
    public Integer getSelfRenewMins() {
        return selfRenewMins;
    }
    public Group setMaxMembers(Integer maxMembers) {
        this.maxMembers = maxMembers;
        return this;
    }
    public Integer getMaxMembers() {
        return maxMembers;
    }
    public Group setResourceOwnership(ResourceGroupOwnership resourceOwnership) {
        this.resourceOwnership = resourceOwnership;
        return this;
    }
    public ResourceGroupOwnership getResourceOwnership() {
        return resourceOwnership;
    }
    public Group setPrincipalDomainFilter(String principalDomainFilter) {
        this.principalDomainFilter = principalDomainFilter;
        return this;
    }
    public String getPrincipalDomainFilter() {
        return principalDomainFilter;
    }
    public Group setNotifyDetails(String notifyDetails) {
        this.notifyDetails = notifyDetails;
        return this;
    }
    public String getNotifyDetails() {
        return notifyDetails;
    }
    public Group setName(String name) {
        this.name = name;
        return this;
    }
    public String getName() {
        return name;
    }
    public Group setModified(Timestamp modified) {
        this.modified = modified;
        return this;
    }
    public Timestamp getModified() {
        return modified;
    }
    public Group setGroupMembers(List<GroupMember> groupMembers) {
        this.groupMembers = groupMembers;
        return this;
    }
    public List<GroupMember> getGroupMembers() {
        return groupMembers;
    }
    public Group setAuditLog(List<GroupAuditLog> auditLog) {
        this.auditLog = auditLog;
        return this;
    }
    public List<GroupAuditLog> getAuditLog() {
        return auditLog;
    }

    @Override
    public boolean equals(Object another) {
        if (this != another) {
            if (another == null || another.getClass() != Group.class) {
                return false;
            }
            Group a = (Group) another;
            if (selfServe == null ? a.selfServe != null : !selfServe.equals(a.selfServe)) {
                return false;
            }
            if (reviewEnabled == null ? a.reviewEnabled != null : !reviewEnabled.equals(a.reviewEnabled)) {
                return false;
            }
            if (notifyRoles == null ? a.notifyRoles != null : !notifyRoles.equals(a.notifyRoles)) {
                return false;
            }
            if (userAuthorityFilter == null ? a.userAuthorityFilter != null : !userAuthorityFilter.equals(a.userAuthorityFilter)) {
                return false;
            }
            if (userAuthorityExpiration == null ? a.userAuthorityExpiration != null : !userAuthorityExpiration.equals(a.userAuthorityExpiration)) {
                return false;
            }
            if (memberExpiryDays == null ? a.memberExpiryDays != null : !memberExpiryDays.equals(a.memberExpiryDays)) {
                return false;
            }
            if (serviceExpiryDays == null ? a.serviceExpiryDays != null : !serviceExpiryDays.equals(a.serviceExpiryDays)) {
                return false;
            }
            if (tags == null ? a.tags != null : !tags.equals(a.tags)) {
                return false;
            }
            if (auditEnabled == null ? a.auditEnabled != null : !auditEnabled.equals(a.auditEnabled)) {
                return false;
            }
            if (deleteProtection == null ? a.deleteProtection != null : !deleteProtection.equals(a.deleteProtection)) {
                return false;
            }
            if (lastReviewedDate == null ? a.lastReviewedDate != null : !lastReviewedDate.equals(a.lastReviewedDate)) {
                return false;
            }
            if (selfRenew == null ? a.selfRenew != null : !selfRenew.equals(a.selfRenew)) {
                return false;
            }
            if (selfRenewMins == null ? a.selfRenewMins != null : !selfRenewMins.equals(a.selfRenewMins)) {
                return false;
            }
            if (maxMembers == null ? a.maxMembers != null : !maxMembers.equals(a.maxMembers)) {
                return false;
            }
            if (resourceOwnership == null ? a.resourceOwnership != null : !resourceOwnership.equals(a.resourceOwnership)) {
                return false;
            }
            if (principalDomainFilter == null ? a.principalDomainFilter != null : !principalDomainFilter.equals(a.principalDomainFilter)) {
                return false;
            }
            if (notifyDetails == null ? a.notifyDetails != null : !notifyDetails.equals(a.notifyDetails)) {
                return false;
            }
            if (name == null ? a.name != null : !name.equals(a.name)) {
                return false;
            }
            if (modified == null ? a.modified != null : !modified.equals(a.modified)) {
                return false;
            }
            if (groupMembers == null ? a.groupMembers != null : !groupMembers.equals(a.groupMembers)) {
                return false;
            }
            if (auditLog == null ? a.auditLog != null : !auditLog.equals(a.auditLog)) {
                return false;
            }
        }
        return true;
    }
}
