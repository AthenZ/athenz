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

package com.yahoo.athenz.common.server.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.util.StringUtils;
import com.yahoo.athenz.common.config.AuthzDetailsEntity;
import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.zms.*;
import com.yahoo.rdl.Struct;
import com.yahoo.rdl.Timestamp;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class AuthzHelper {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthzHelper.class);

    private static final String ASSUME_ROLE = "assume_role";
    private static final ObjectMapper JSON_MAPPER = initJsonMapper();

    static ObjectMapper initJsonMapper() {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
        return objectMapper;
    }

    private static boolean isUpdateRequired(RoleMember member1, RoleMember member2) {
        return !Objects.equals(member1.getExpiration(), member2.getExpiration()) ||
                !Objects.equals(member1.getReviewReminder(), member2.getReviewReminder());
    }

    public static void removeRoleMembers(List<RoleMember> originalRoleMembers, List<RoleMember> removeRoleMembers, boolean filterByNameOnly) {
        if (removeRoleMembers == null || originalRoleMembers == null) {
            return;
        }
        for (RoleMember removeMember : removeRoleMembers) {
            originalRoleMembers.removeIf(item ->
                    item.getMemberName().equalsIgnoreCase(removeMember.getMemberName()) &&
                    (filterByNameOnly || !isUpdateRequired(item, removeMember)));
        }
    }

    private static boolean isGroupMemberExpirationChanged(GroupMember member1, GroupMember member2) {
        return !Objects.equals(member1.getExpiration(), member2.getExpiration());
    }

    public static void removeGroupMembers(List<GroupMember> originalGroupMembers, List<GroupMember> removeGroupMembers, boolean filterByNameOnly) {
        if (removeGroupMembers == null || originalGroupMembers == null) {
            return;
        }
        for (GroupMember removeMember : removeGroupMembers) {
            originalGroupMembers.removeIf(item ->
                    item.getMemberName().equalsIgnoreCase(removeMember.getMemberName()) &&
                            (filterByNameOnly || !isGroupMemberExpirationChanged(item, removeMember)));
        }
    }

    public static boolean isMemberDisabled(Integer systemDisabled) {
        return systemDisabled != null && systemDisabled != 0;
    }

    public static boolean isMemberExpired(Timestamp expiration, long currentTime) {
        return (expiration != null && expiration.millis() < currentTime);
    }

    public static boolean shouldSkipGroupMember(GroupMember member, long currentTime) {
        return isMemberDisabled(member.getSystemDisabled()) || isMemberExpired(member.getExpiration(), currentTime);
    }

    public static boolean isMemberOfGroup(List<GroupMember> groupMembers, final String member) {
        if (groupMembers == null) {
            return false;
        }
        return checkGroupMemberValidity(groupMembers, member);
    }

    public static boolean checkGroupMemberValidity(List<GroupMember> groupMembers, final String member) {

        // we need to make sure that both the user is not expired
        // and not disabled by the system

        boolean isMember = false;
        long currentTime = System.currentTimeMillis();

        for (GroupMember memberInfo: groupMembers) {
            final String memberName = memberInfo.getMemberName();
            if (memberNameMatch(memberName, member)) {
                isMember = !isMemberDisabled(memberInfo.getSystemDisabled()) && !isMemberExpired(memberInfo.getExpiration(), currentTime);
                break;
            }
        }
        return isMember;
    }

    public static boolean memberNameMatch(final String memberName, final  String matchName) {

        // we are supporting 4 formats for role members
        // *, <domain>.[user]*, <domain>.<user>, and <domain>:group.<group-name>
        // special handling for wildcards only

        if (memberName.equals("*")) {
            return true;
        } else if (memberName.endsWith("*")) {
            return matchName.startsWith(memberName.substring(0, memberName.length() - 1));
        } else {
            return memberName.equals(matchName);
        }
    }

    public static boolean shouldRunDelegatedTrustCheck(final String trust, final String trustDomain) {

        // if no trust field then no delegated trust check

        if (trust == null) {
            return false;
        }

        // if no specific trust domain specifies then we need
        // run the delegated trust check for this domain

        if (trustDomain == null) {
            return true;
        }

        // otherwise we'll run the delegated trust check only if
        // domain name matches

        return trust.equalsIgnoreCase(trustDomain);
    }

    public static String retrieveResourceDomain(String resource, String op, String trustDomain) {

        // special handling for ASSUME_ROLE assertions. Since any assertion with
        // that action refers to a resource in another domain, there is no point
        // to retrieve the domain name from the resource. In these cases the caller
        // must specify the trust domain attribute so we'll use that instead and
        // if one is not specified then we'll fall back to using the domain name
        // from the resource

        String domainName;
        if (ASSUME_ROLE.equalsIgnoreCase(op) && trustDomain != null) {
            domainName = trustDomain;
        } else {
            domainName = extractResourceDomainName(resource);
        }
        return domainName;
    }

    public static String extractResourceDomainName(final String resource) {
        int idx = resource.indexOf(':');
        if (idx == -1) {
            return null;
        }
        return resource.substring(0, idx);
    }

    public static String lowerDomainInResource(final String resource) {
        if (resource == null) {
            return null;
        }

        int idx = resource.indexOf(':');
        if (idx == -1) {
            return resource;
        }

        // most requests already have the domain in lower case so
        // we'll avoid creating a new string object in that case

        final String domainName = resource.substring(0, idx);
        final String lowerDomainName = domainName.toLowerCase();
        if (domainName.equals(lowerDomainName)) {
            return resource;
        }
        return lowerDomainName + resource.substring(idx);
    }

    // enum to represent how we handle assertions that were created with
    // the case-sensitive flag:
    //   DISABLED - action and resource are matched case-insensitive
    //   MONITOR  - action and resource are matched case-insensitive but
    //              we log any assertion that only matched because case
    //              was ignored
    //   ENFORCE  - action and resource are matched in their original case
    // regardless of the server mode, if the caller requests case-sensitive
    // check, then the assertions are matched in their original case

    public enum CaseSensitiveMode {
        DISABLED,
        MONITOR,
        ENFORCE
    }

    public static CaseSensitiveMode parseCaseSensitiveMode(final String value) {
        try {
            return CaseSensitiveMode.valueOf(value.toUpperCase());
        } catch (IllegalArgumentException ex) {
            LOGGER.error("Invalid case-sensitive authorization mode: {}, using disabled", value);
            return CaseSensitiveMode.DISABLED;
        }
    }

    /**
     * Check if the action and resource match the given assertion. The action
     * and resource values must be in lower case while the actionExact and
     * resourceExact values must be in their original case with only the domain
     * part of the resource in lower case. The exact values are only required
     * if the mode is not DISABLED.
     * @param assertion assertion to check against
     * @param action action value in lower case
     * @param resource resource value in lower case
     * @param actionExact action value in its original case
     * @param resourceExact resource value in its original case
     * @param mode case-sensitive mode for the request
     * @param domainName name of the domain the assertion belongs to
     * @return true if the action and resource match the assertion
     */
    public static boolean assertionActionResourceMatch(Assertion assertion, final String action,
            final String resource, final String actionExact, final String resourceExact,
            CaseSensitiveMode mode, final String domainName) {

        final boolean caseSensitiveAssertion = assertion.getCaseSensitive() == Boolean.TRUE;

        // for case-sensitive assertions in enforce mode we match the action
        // and resource against the original request values

        if (caseSensitiveAssertion && mode == CaseSensitiveMode.ENFORCE) {
            return assertionExactActionResourceMatch(assertion, actionExact, resourceExact);
        }

        // Lowercase action and resource as it is possible to store them case-sensitive

        String actionPattern = StringUtils.patternFromGlob(assertion.getAction().toLowerCase());
        if (!action.matches(actionPattern)) {
            return false;
        }

        String rezPattern = StringUtils.patternFromGlob(assertion.getResource().toLowerCase());
        if (!resource.matches(rezPattern)) {
            return false;
        }

        // in monitor mode we log any case-sensitive assertion that has
        // matched only because the case was ignored. we don't change
        // the result of the check

        if (caseSensitiveAssertion && mode == CaseSensitiveMode.MONITOR
                && !assertionExactActionResourceMatch(assertion, actionExact, resourceExact)) {
            LOGGER.warn("case-sensitive assertion matched only case-insensitive: domain: {}, assertion: {}/{}/{}/{},"
                    + " request action: {}, resource: {}", domainName, assertion.getRole(), assertion.getAction(),
                    assertion.getResource(), assertion.getEffect(), actionExact, resourceExact);
        }

        return true;
    }

    static boolean assertionExactActionResourceMatch(Assertion assertion, final String actionExact,
            final String resourceExact) {
        return actionExact.matches(StringUtils.patternFromGlob(assertion.getAction()))
                && resourceExact.matches(StringUtils.patternFromGlob(assertion.getResource()));
    }

    public static boolean authorityAuthorizationAllowed(Principal principal) {

        Authority authority = principal.getAuthority();
        if (authority == null) {
            return true;
        }

        return authority.allowAuthorization();
    }

    public static boolean checkRoleMemberValidity(List<RoleMember> roleMembers, final String member,
                                                  GroupMembersFetcher groupMembersFetcher) {

        // we need to make sure that both the user is not expired
        // and not disabled by the system. the members can also
        // include groups so that means even if we get a response
        // from one group that is expired, we can't just stop
        // and need to check the other groups as well.
        // For efficiency reasons we'll process groups at the
        // end so in case we get a match in a role there is no
        // need to look at the groups at all

        List<RoleMember> groupMembers = new ArrayList<>();
        for (RoleMember memberInfo: roleMembers) {
            if (memberInfo.getPrincipalType() != null && memberInfo.getPrincipalType() == Principal.Type.GROUP.getValue()) {
                groupMembers.add(memberInfo);
            }
        }

        // first only process regular members

        boolean isMember = false;
        long currentTime = System.currentTimeMillis();
        for (RoleMember memberInfo: roleMembers) {
            if (memberInfo.getPrincipalType() != null && memberInfo.getPrincipalType() == Principal.Type.GROUP.getValue()) {
                continue;
            }
            final String memberName = memberInfo.getMemberName();
            if (memberNameMatch(memberName, member)) {
                isMember = !isMemberDisabled(memberInfo.getSystemDisabled()) && !isMemberExpired(memberInfo.getExpiration(), currentTime);
                break;
            }
        }

        // if we have a match or no group members then we're done

        if (isMember || groupMembers.isEmpty()) {
            return isMember;
        }

        // now let's process our groups

        for (RoleMember memberInfo : groupMembers) {

            // if the group is expired there is no need to check

            if (isMemberExpired(memberInfo.getExpiration(), currentTime)) {
                continue;
            }
            isMember = isMemberOfGroup(groupMembersFetcher.getGroupMembers(memberInfo.getMemberName()), member);
            if (isMember) {
                break;
            }
        }
        return isMember;
    }

    public static boolean isMemberOfRole(Role role, final String member, GroupMembersFetcher groupMembersFetcher) {

        final List<RoleMember> members = role.getRoleMembers();
        if (members == null) {
            return false;
        }

        return checkRoleMemberValidity(members, member, groupMembersFetcher);
    }

    public static boolean assumeRoleNameMatch(final String roleName, Assertion assertion) {

        if (!ASSUME_ROLE.equalsIgnoreCase(assertion.getAction())) {
            return false;
        }

        return roleName.equals(assertion.getRole());
    }

    public static boolean assumeRoleResourceMatch(String roleName, Assertion assertion) {

        if (!ASSUME_ROLE.equalsIgnoreCase(assertion.getAction())) {
            return false;
        }

        String rezPattern = StringUtils.patternFromGlob(assertion.getResource());
        return roleName.matches(rezPattern);
    }

    public static boolean matchDelegatedTrustPolicy(Policy policy, final String roleName, final String roleMember,
                                                    List<Role> roles, GroupMembersFetcher groupMembersFetcher) {

        List<Assertion> assertions = policy.getAssertions();
        if (assertions == null) {
            return false;
        }

        for (Assertion assertion : assertions) {
            if (matchDelegatedTrustAssertion(assertion, roleName, roleMember, roles, groupMembersFetcher)) {
                return true;
            }
        }

        return false;
    }

    public static boolean matchDelegatedTrustAssertion(Assertion assertion, final String roleName, final String roleMember,
                                                       List<Role> roles, GroupMembersFetcher groupMembersFetcher) {

        if (!assumeRoleResourceMatch(roleName, assertion)) {
            return false;
        }

        String rolePattern = StringUtils.patternFromGlob(assertion.getRole());
        for (Role role : roles) {
            String name = role.getName();
            if (!name.matches(rolePattern)) {
                continue;
            }

            if (isMemberOfRole(role, roleMember, groupMembersFetcher)) {
                return true;
            }
        }

        return false;
    }

    public static AuthzDetailsEntity convertEntityToAuthzDetailsEntity(Entity entity)
            throws JsonProcessingException, ServerResourceException {

        Struct value = entity.getValue();
        if (value == null) {
            throw new ServerResourceException(ServerResourceException.BAD_REQUEST, "Entity has no value");
        }
        // the authorization details is the value of the data field
        final String authzDetails = value.getString("data");
        if (StringUtil.isEmpty(authzDetails)) {
            throw new ServerResourceException(ServerResourceException.BAD_REQUEST, "Entity has no data field");
        }
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Authorization Details json input: {}", authzDetails);
        }
        return JSON_MAPPER.readValue(authzDetails, AuthzDetailsEntity.class);
    }

    /**
     * Extract group members for a given group name
     */
    public interface GroupMembersFetcher {
        /**
         *
         * @param groupName name of a group
         * @return group members extracted from the given group
         */
        List<GroupMember> getGroupMembers(String groupName);
    }

}
