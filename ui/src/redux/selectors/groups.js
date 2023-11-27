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
import { groupDelimiter } from '../config';

export const thunkSelectGroups = (state) => {
    return state.groups.groups ? state.groups.groups : {};
};

export const thunkSelectGroup = (state, domainName, groupName) => {
    return selectGroup(state, domainName, groupName);
};

export const selectGroups = (state) => {
    return state.groups.groups ? mapToList(state.groups.groups) : [];
};

export const selectGroup = (state, domainName, groupName) => {
    return state.groups.groups &&
        state.groups.groups[getFullName(domainName, groupDelimiter, groupName)]
        ? state.groups.groups[
              getFullName(domainName, groupDelimiter, groupName)
          ]
        : {};
};

export const thunkSelectGroupMembers = (state, domainName, groupName) => {
    return selectGroup(state, domainName, groupName).groupMembers || {};
};

export const selectGroupMembers = (state, domainName, groupName) => {
    return state.groups.groups &&
        state.groups.groups[getFullName(domainName, groupDelimiter, groupName)]
        ? membersMapsToList(
              state.groups.groups[
                  getFullName(domainName, groupDelimiter, groupName)
              ].groupMembers,
              state.groups.groups[
                  getFullName(domainName, groupDelimiter, groupName)
              ].groupPendingMembers
          )
        : [];
};

export const thunkSelectGroupMember = (
    state,
    domainName,
    groupName,
    memberName
) => {
    return (
        thunkSelectGroupMembers(state, domainName, groupName)[memberName] || {}
    );
};

export const selectReviewGroupMembers = (state, domainName, groupName) => {
    let members = selectGroupMembers(state, domainName, groupName);
    return members.filter((m) => m.approved);
};

export const selectGroupHistory = (state, domainName, groupName) => {
    return state.groups.groups &&
        state.groups.groups[
            getFullName(domainName, groupDelimiter, groupName)
        ] &&
        state.groups.groups[getFullName(domainName, groupDelimiter, groupName)]
            .auditLog
        ? state.groups.groups[
              getFullName(domainName, groupDelimiter, groupName)
          ].auditLog
        : [];
};

export const selectGroupRoleMembers = (state, domainName, groupName) => {
    return state.groups.groups &&
        state.groups.groups[
            getFullName(domainName, groupDelimiter, groupName)
        ] &&
        state.groups.groups[getFullName(domainName, groupDelimiter, groupName)]
            .roleMembers
        ? state.groups.groups[
              getFullName(domainName, groupDelimiter, groupName)
          ].roleMembers
        : [];
};

export const selectGroupTags = (state, domainName, groupName) => {
    return state.groups.groups &&
        state.groups.groups[
            getFullName(domainName, groupDelimiter, groupName)
        ] &&
        state.groups.groups[getFullName(domainName, groupDelimiter, groupName)]
            .tags
        ? state.groups.groups[
              getFullName(domainName, groupDelimiter, groupName)
          ].tags
        : {};
};

export const selectUserReviewGroups = (state) => {
    return state.groups.groupsToReview ? state.groups.groupsToReview : [];
};
