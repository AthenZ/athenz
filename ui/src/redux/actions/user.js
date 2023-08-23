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

export const LOAD_PENDING_MEMBERS = 'LOAD_PENDING_MEMBERS';
export const loadUserPendingMembers = (pendingMembers, expiry) => ({
    type: LOAD_PENDING_MEMBERS,
    payload: {
        pendingMembers,
        expiry,
    },
});
export const LOAD_RESOURCE_ACCESS_LIST = 'LOAD_RESOURCE_ACCESS_LIST';
export const loadUserResourceAccessList = (resourceAccessList, expiry) => ({
    type: LOAD_RESOURCE_ACCESS_LIST,
    payload: {
        resourceAccessList,
        expiry,
    },
});
export const RETURN_USER_RESOURCE_ACCESS_LIST =
    'RETURN_USER_RESOURCE_ACCESS_LIST';
export const returnUserResourceAccessList = () => ({
    type: RETURN_USER_RESOURCE_ACCESS_LIST,
});

export const ADD_ALL_USERS = 'ADD_ALL_USERS';
export const addUsersToStore = (userList) => ({
    type: ADD_ALL_USERS,
    payload: {
        userList: userList,
    },
});
