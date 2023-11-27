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

export const LOAD_GROUPS = 'LOAD_GROUPS';
export const loadGroups = (groups, domainName, expiry) => ({
    type: LOAD_GROUPS,
    payload: {
        groups: groups,
        domainName: domainName,
        expiry: expiry,
    },
});

export const LOAD_GROUPS_TO_REVIEW = 'LOAD_GROUPS_TO_REVIEW';
export const loadGroupsToReview = (groupsToReview) => ({
    type: LOAD_GROUPS_TO_REVIEW,
    payload: { groupsToReview: groupsToReview },
});

export const RETURN_GROUPS_TO_REVIEW = 'RETURN_GROUPS_TO_REVIEW';
export const returnGroupsToReview = () => ({
    type: RETURN_GROUPS_TO_REVIEW,
});

export const RETURN_GROUPS = 'RETURN_GROUPS';
export const returnGroups = () => ({
    type: RETURN_GROUPS,
});

export const ADD_GROUP_TO_STORE = 'ADD_GROUP_TO_STORE';
export const addGroupToStore = (groupData) => ({
    type: ADD_GROUP_TO_STORE,
    payload: {
        groupData: groupData,
    },
});

export const DELETE_GROUP_FROM_STORE = 'DELETE_GROUP_FROM_STORE';
export const deleteGroupFromStore = (groupName) => ({
    type: DELETE_GROUP_FROM_STORE,
    payload: {
        groupName: groupName,
    },
});

export const LOAD_GROUP = 'LOAD_GROUP';
export const loadGroup = (groupData, groupName) => ({
    type: LOAD_GROUP,
    payload: {
        groupData: groupData,
        groupName: groupName,
    },
});

export const LOAD_GROUP_ROLE_MEMBERS = 'LOAD_GROUP_ROLE_MEMBERS';
export const loadGroupRoleMembers = (groupName, roleMembers) => ({
    type: LOAD_GROUP_ROLE_MEMBERS,
    payload: {
        groupName,
        roleMembers,
    },
});

export const RETURN_ROLE_MEMBERS = 'RETURN_ROLE_MEMBERS';
export const returnRoleMembers = () => ({
    type: RETURN_ROLE_MEMBERS,
});

export const REVIEW_GROUP = 'REVIEW_GROUP';
export const reviewGroupToStore = (groupName, reviewedGroup) => ({
    type: REVIEW_GROUP,
    payload: {
        groupName,
        reviewedGroup,
    },
});
