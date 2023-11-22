/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

import { getFullName, mapToList, membersMapsToList } from '../utils';
import { roleDelimiter } from '../config';
import { thunkSelectGroupMembers } from './groups';

export const thunkSelectRoles = (state) => {
    return state.roles.roles ? state.roles.roles : {};
};

export const thunkSelectRole = (state, domainName, roleName) => {
    return selectRole(state, domainName, roleName);
};

export const thunkSelectRoleMembers = (state, domainName, roleName) => {
    return state.roles.roles &&
        state.roles.roles[getFullName(domainName, roleDelimiter, roleName)] &&
        state.roles.roles[getFullName(domainName, roleDelimiter, roleName)]
            .roleMembers
        ? state.roles.roles[getFullName(domainName, roleDelimiter, roleName)]
              .roleMembers
        : {};
};

export const thunkSelectRoleMember = (
    state,
    domainName,
    roleName,
    memberName
) => {
    return (
        thunkSelectRoleMembers(state, domainName, roleName)[memberName] || {}
    );
};

export const selectRoles = (state) => {
    return state.roles.roles ? mapToList(state.roles.roles) : [];
};

const buildUserMapFromRoles = (roles) => {
    let userMap = {};
    for (const [roleName, role] of Object.entries(roles)) {
        for (let [memberName, member] of Object.entries(role.roleMembers)) {
            if (userMap[memberName]) {
                userMap[memberName].memberRoles.push({
                    roleName: roleName,
                    expiration: member.expiration,
                });
            } else {
                userMap[member.memberName] = { ...member };
                userMap[member.memberName].memberRoles = [
                    {
                        roleName: roleName,
                        expiration: member.expiration,
                    },
                ];
            }
        }
    }
    return userMap;
};

export const selectRoleUsers = (state) => {
    return state.roles.roles
        ? mapToList(buildUserMapFromRoles(state.roles.roles))
        : [];
};

export const selectRole = (state, domainName, roleName) => {
    return state.roles.roles &&
        state.roles.roles[getFullName(domainName, roleDelimiter, roleName)]
        ? state.roles.roles[getFullName(domainName, roleDelimiter, roleName)]
        : {};
};

export const selectRoleMembers = (state, domainName, roleName) => {
    return state.roles.roles &&
        state.roles.roles[getFullName(domainName, roleDelimiter, roleName)] &&
        state.roles.roles[getFullName(domainName, roleDelimiter, roleName)]
            .roleMembers
        ? membersMapsToList(
              state.roles.roles[
                  getFullName(domainName, roleDelimiter, roleName)
              ].roleMembers,
              state.roles.roles[
                  getFullName(domainName, roleDelimiter, roleName)
              ].rolePendingMembers
          )
        : [];
};

export const selectReviewRoleMembers = (state, domainName, roleName) => {
    let members = selectRoleMembers(state, domainName, roleName);
    return members.filter((m) => m.approved !== false);
};

export const selectRoleTags = (state, domainName, roleName) => {
    return state.roles.roles &&
        state.roles.roles[getFullName(domainName, roleDelimiter, roleName)] &&
        state.roles.roles[getFullName(domainName, roleDelimiter, roleName)].tags
        ? state.roles.roles[getFullName(domainName, roleDelimiter, roleName)]
              .tags
        : {};
};

export const selectRoleHistory = (state, domainName, roleName) => {
    return state.roles.roles &&
        state.roles.roles[getFullName(domainName, roleDelimiter, roleName)] &&
        state.roles.roles[getFullName(domainName, roleDelimiter, roleName)]
            .auditLog
        ? state.roles.roles[getFullName(domainName, roleDelimiter, roleName)]
              .auditLog
        : [];
};

export const selectUserReviewRoles = (state) => {
    return state.roles.rolesToReview ? state.roles.rolesToReview : [];
};
