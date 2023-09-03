/*
 *
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
 *
 */

package com.yahoo.athenz.zts.store;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.yahoo.athenz.common.server.util.AuthzHelper;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.RoleMember;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

public class RequireRoleCertCache {
    final Cache<String, List<RoleMemberCache>> roleMemberRequireCertCache;
    final Cache<String, List<RoleMemberCache>> principalRoleRequireCertCache;
    final PrefixTrie requireRoleCertPrefixTrie;
    final Set<String> requireRoleCertWildcard;

    public RequireRoleCertCache() {
        roleMemberRequireCertCache = CacheBuilder.newBuilder().concurrencyLevel(25).build();
        principalRoleRequireCertCache = CacheBuilder.newBuilder().concurrencyLevel(25).build();
        requireRoleCertPrefixTrie = new RolePrefixTrie();
        requireRoleCertWildcard = ConcurrentHashMap.newKeySet();
    }

    void processRoleCache(Role role) {
        final List<RoleMemberCache> collectionMembers = getRoleMembersForCache(role);
        // obtain the previous list of members for the collection
        // and determine the list of changes between old and new members

        List<RoleMemberCache> originalMembers = roleMemberRequireCertCache.getIfPresent(role.getName());
        List<RoleMemberCache> curMembers = originalMembers == null ? new ArrayList<>() : new ArrayList<>(originalMembers);
        List<RoleMemberCache> delMembers = new ArrayList<>(curMembers);
        List<RoleMemberCache> newMembers = new ArrayList<>(collectionMembers);
        List<RoleMemberCache> updMembers = new ArrayList<>(collectionMembers);

        // remove current members from new members
        removeRoleMembersCache(newMembers, curMembers);

        // remove new members from current members
        // which leaves the deleted members.

        removeRoleMembersCache(delMembers, collectionMembers);

        // now let's remove our new members from the member list to
        // get the possible list of users that need to be updated

        removeRoleMembersCache(updMembers, newMembers);

        // update the collection member cache with the new members

        roleMemberRequireCertCache.put(role.getName(), collectionMembers);

        // first process the updated entries

        long currentTime = System.currentTimeMillis();
        for (RoleMemberCache member : updMembers) {

            // it's possible that initially we skipped the entry because it was
            // disabled or expired so we might have no entries in the map

            List<RoleMemberCache> members = principalRoleRequireCertCache.getIfPresent(member.getRoleMember().getMemberName());
            if (members == null) {

                // make sure we want to process this user

                if (shouldSkipRoleMember(member, currentTime)) {
                    continue;
                }

                // otherwise we'll add this member to our new list

                members = new ArrayList<>();
                members.add(member);
                principalRoleRequireCertCache.put(member.getRoleMember().getMemberName(), members);

            } else {

                // if we need to skip the entry then we'll delete the member
                // from our list otherwise we'll just update it

                if (shouldSkipRoleMember(member, currentTime)) {
                    members.removeIf(item -> item.getRole().equalsIgnoreCase(role.getName()));
                } else {
                    // we need to find our entry and update details

                    for (RoleMemberCache mbr : members) {
                        if (mbr.getRole().equalsIgnoreCase(role.getName())) {
                            mbr.getRoleMember().setExpiration(member.getRoleMember().getExpiration());
                            mbr.getRoleMember().setSystemDisabled(member.getRoleMember().getSystemDisabled());
                            mbr.getRoleMember().setActive(member.getRoleMember().getActive());
                            mbr.getRoleMember().setApproved(member.getRoleMember().getApproved());
                            mbr.setRole(member.getRole());
                            break;
                        }
                    }
                }
            }
        }

        // now let's add our new members

        for (RoleMemberCache member : newMembers) {

            // skip any disabled and expired users

            if (shouldSkipRoleMember(member, currentTime)) {
                continue;
            }

            List<RoleMemberCache> members = principalRoleRequireCertCache.getIfPresent(member.getRoleMember().getMemberName());
            if (members == null) {
                members = new ArrayList<>();
                principalRoleRequireCertCache.put(member.getRoleMember().getMemberName(), members);
            }
            members.add(member);

            if (member.getRoleMember().getMemberName().equals("*")) {
                requireRoleCertWildcard.add(role.getName());
            } else if (member.getRoleMember().getMemberName().endsWith("*")) {
                requireRoleCertPrefixTrie.insert(member.getRoleMember().getMemberName(), role.getName());
            }
        }

        // process deleted members from the collection

        processCollectionDeletedMembers(role.getName(), delMembers);
    }

    void processRoleCacheDelete(Role role) {
        // first remove the group from our cache

        roleMemberRequireCertCache.invalidate(role.getName());

        // delete all the members from our cache objects

        processCollectionDeletedMembers(role.getName(), getRoleMembersForCache(role));
    }

    public List<String> getRolesRequireRoleCert(String principal) {
        List<RoleMemberCache> roleMembers = principalRoleRequireCertCache.getIfPresent(principal);
        if (roleMembers == null) {
            roleMembers = new ArrayList<>();
        }
        List<String> roles = roleMembers.stream().map(RoleMemberCache::getRole).collect(Collectors.toList());
        roles.addAll(requireRoleCertWildcard);
        roles.addAll(requireRoleCertPrefixTrie.findMatchingValues(principal));
        return roles;
    }

    void processCollectionDeletedMembers(final String collectionName,
                                         List<RoleMemberCache> deletedMembers) {

        // if the group has no members then we have nothing to do

        if (deletedMembers == null) {
            return;
        }
        for (RoleMemberCache member : deletedMembers) {
            String memberName = member.getRoleMember().getMemberName();
            List<RoleMemberCache> members = principalRoleRequireCertCache.getIfPresent(memberName);
            if (members == null) {
                continue;
            }
            members.removeIf(item -> item.getRole().equalsIgnoreCase(collectionName));

            if (memberName.equals("*")) {
                requireRoleCertWildcard.remove(collectionName);
            } else if (memberName.endsWith("*")) {
                requireRoleCertPrefixTrie.delete(memberName, collectionName);
            }
        }
    }

    private List<RoleMemberCache> getRoleMembersForCache(Role role) {

        if (role.getRoleMembers() == null || role.getRoleMembers().isEmpty()) {
            return new ArrayList<>();
        }

        return role.getRoleMembers()
                .stream()
                .map(roleMember -> new RoleMemberCache(roleMember, role.getName()))
                .collect(Collectors.toList());
    }

    private static void removeRoleMembersCache(List<RoleMemberCache> originalRoleMembers, List<RoleMemberCache> removeRoleMembers) {
        for (RoleMemberCache removeMember : removeRoleMembers) {
            originalRoleMembers.removeIf(item -> item.getRoleMember().getMemberName().equalsIgnoreCase(removeMember.getRoleMember().getMemberName()));
        }
    }

    private static boolean shouldSkipRoleMember(RoleMemberCache member, long currentTime) {
        return AuthzHelper.isMemberDisabled(member.getRoleMember().getSystemDisabled()) ||
                AuthzHelper.isMemberExpired(member.getRoleMember().getExpiration(), currentTime);
    }

    static class RoleMemberCache {
        public RoleMemberCache(RoleMember roleMember, String role) {
            this.roleMember = roleMember;
            this.role = role;
        }

        RoleMember roleMember;
        String role;

        public RoleMember getRoleMember() {
            return roleMember;
        }

        public String getRole() {
            return role;
        }

        public void setRole(String role) {
            this.role = role;
        }
    }
}
