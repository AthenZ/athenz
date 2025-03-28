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

export const selectUserPendingMembers = (state) =>
    state.user.pendingMembers ? state.user.pendingMembers : [];
export const selectUserResourceAccessList = (state) =>
    state.user.resourceAccessList ? state.user.resourceAccessList : [];

export const selectAllUsers = (state) => {
    return state.user.userList;
};

export const selectPendingMemberRole = (state, domainName, roleName) =>
    state?.user?.pendingMemberRoles?.[`${domainName}:${roleName}`] ?? null;
export const selectPendingMemberGroup = (state, domainName, groupName) =>
    state?.user?.pendingMemberGroups?.[`${domainName}:${groupName}`] ?? null;
