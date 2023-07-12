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

export const ADD_MEMBER_TO_STORE = 'ADD_MEMBER_TO_STORE';
export const addMemberToStore = (member, category, collectionName) => ({
    type: ADD_MEMBER_TO_STORE,
    payload: {
        member,
        category,
        collectionName,
    },
});

export const ADD_PENDING_MEMBER_TO_STORE = 'ADD_PENDING_MEMBER_TO_STORE';
export const addPendingMemberToStore = (member, category, collectionName) => ({
    type: ADD_PENDING_MEMBER_TO_STORE,
    payload: {
        member,
        category,
        collectionName,
    },
});

export const DELETE_MEMBER_FROM_STORE = 'DELETE_MEMBER_FROM_STORE';
export const deleteMemberFromStore = (
    memberName,
    category,
    collectionName
) => ({
    type: DELETE_MEMBER_FROM_STORE,
    payload: {
        memberName,
        category,
        collectionName,
    },
});

export const DELETE_PENDING_MEMBER_FROM_STORE =
    'DELETE_PENDING_MEMBER_FROM_STORE';
export const deletePendingMemberFromStore = (
    memberName,
    category,
    collectionName
) => ({
    type: DELETE_PENDING_MEMBER_FROM_STORE,
    payload: {
        memberName,
        category,
        collectionName,
    },
});

export const UPDATE_SETTING_TO_STORE = 'UPDATE_SETTING_TO_STORE';
export const updateSettingsToStore = (
    collectionName,
    collectionSettings,
    category
) => ({
    type: UPDATE_SETTING_TO_STORE,
    payload: {
        collectionName,
        collectionSettings,
        category,
    },
});

export const UPDATE_TAGS_TO_STORE = 'UPDATE_TAGS_TO_STORE';
export const updateTagsToStore = (
    collectionName,
    collectionWithTags,
    category
) => ({
    type: UPDATE_TAGS_TO_STORE,
    payload: {
        collectionName,
        collectionWithTags,
        category,
    },
});
