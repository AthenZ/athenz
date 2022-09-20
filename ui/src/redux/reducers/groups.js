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

import {
    ADD_GROUP_TO_STORE,
    DELETE_GROUP_FROM_STORE,
    LOAD_GROUP,
    LOAD_GROUP_ROLE_MEMBERS,
    LOAD_GROUPS,
    RETURN_GROUPS,
    REVIEW_GROUP,
} from '../actions/groups';
import {
    ADD_MEMBER_TO_STORE,
    DELETE_MEMBER_FROM_STORE,
    UPDATE_SETTING_TO_STORE,
    UPDATE_TAGS_TO_STORE,
} from '../actions/collections';
import produce from 'immer';

export const groups = (state = {}, action) => {
    const { type, payload } = action;
    switch (type) {
        // we load the groups in that way because and we dont want to lose the audit log which we gets in getGroup api call
        case LOAD_GROUPS: {
            const { groups, domainName, expiry } = payload;
            let newState = produce(state, (draft) => {
                draft.domainName = domainName;
                draft.expiry = expiry;
                draft.groups = groups;
            });
            return newState;
        }
        case ADD_GROUP_TO_STORE: {
            const { groupData } = payload;
            let newState = produce(state, (draft) => {
                draft.groups[groupData.name] = groupData;
            });
            return newState;
        }
        case DELETE_GROUP_FROM_STORE: {
            const { groupName } = payload;
            let newState = produce(state, (draft) => {
                delete draft.groups[groupName];
            });
            return newState;
        }
        case ADD_MEMBER_TO_STORE: {
            const { member, category, collectionName } = payload;
            let newState = produce(state, (draft) => {
                if (category === 'group') {
                    if (
                        draft.groups[collectionName] &&
                        draft.groups[collectionName].groupMembers
                    ) {
                        draft.groups[collectionName].groupMembers[
                            member.memberName
                        ] = member;
                    } else {
                        draft.groups[collectionName] = {
                            groupMembers: { [member.memberName]: member },
                        };
                    }
                }
            });
            return newState;
        }
        case DELETE_MEMBER_FROM_STORE: {
            const { memberName, category, collectionName } = payload;
            let newState = produce(state, (draft) => {
                if (category === 'group') {
                    if (
                        draft.groups[collectionName] &&
                        draft.groups[collectionName].groupMembers
                    ) {
                        delete draft.groups[collectionName].groupMembers[
                            memberName
                        ];
                    }
                }
            });
            return newState;
        }
        case UPDATE_TAGS_TO_STORE: {
            const { collectionName, collectionTags, category } = payload;
            let newState = state;
            if (category === 'group') {
                newState = produce(state, (draft) => {
                    if (draft.groups[collectionName]) {
                        draft.groups[collectionName].tags = collectionTags;
                    }
                });
            }
            return newState;
        }
        case LOAD_GROUP: {
            const { groupData, groupName } = payload;
            let newState = produce(state, (draft) => {
                draft.groups[groupName] = groupData;
            });
            return newState;
        }
        case UPDATE_SETTING_TO_STORE: {
            const { collectionName, collectionSettings, category } = payload;
            let newState = state;
            if (category === 'group') {
                newState = produce(state, (draft) => {
                    draft.groups[collectionName] = {
                        ...draft.groups[collectionName],
                        ...collectionSettings,
                    };
                });
            }
            return newState;
        }
        case REVIEW_GROUP: {
            const { groupName, reviewedGroup } = payload;
            const { groupMembers, auditLog, modified, lastReviewedDate } =
                reviewedGroup;
            let newState = produce(state, (draft) => {
                draft.groups[groupName]
                    ? (draft.groups[groupName].groupMembers = groupMembers)
                    : (draft.groups[groupName] = { groupMembers });
                draft.groups[groupName].auditLog = auditLog;
                draft.groups[groupName].modified = modified;
                draft.groups[groupName].lastReviewedDate = lastReviewedDate;
            });
            return newState;
        }
        case LOAD_GROUP_ROLE_MEMBERS: {
            const { groupName, roleMembers } = payload;
            let newState = produce(state, (draft) => {
                draft.groups[groupName]
                    ? (draft.groups[groupName].roleMembers = roleMembers)
                    : (draft.groups[groupName] = { roleMembers });
            });
            return newState;
        }
        case RETURN_GROUPS:
            return state;
        default:
            return state;
    }
};
