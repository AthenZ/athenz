/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import {
    ADD_ROLE_TO_STORE,
    DELETE_ROLE_FROM_STORE,
    LOAD_ROLE,
    LOAD_ROLES,
    LOAD_ROLES_TO_REVIEW,
    MAKE_ROLES_EXPIRES,
    MARKS_ROLE_AS_NEED_REFRESH,
    RETURN_ROLES,
    REVIEW_ROLE,
} from '../actions/roles';
import {
    ADD_MEMBER_TO_STORE,
    ADD_PENDING_MEMBER_TO_STORE,
    DELETE_MEMBER_FROM_STORE,
    DELETE_PENDING_MEMBER_FROM_STORE,
    UPDATE_SETTING_TO_STORE,
    UPDATE_TAGS_TO_STORE,
} from '../actions/collections';
import produce from 'immer';
import { PROCESS_ROLE_PENDING_MEMBERS_TO_STORE } from '../actions/domains';
import { getExpiredTime } from '../utils';
import { getFullCollectionName } from '../thunks/utils/collection';
import { PENDING_STATE_ENUM } from '../../components/constants/constants';

export const roles = (state = {}, action) => {
    const { type, payload } = action;
    switch (type) {
        case LOAD_ROLES: {
            const { roles, domainName, expiry } = payload;
            let newState = produce(state, (draft) => {
                draft.roles = roles;
                draft.domainName = domainName;
                draft.expiry = expiry;
            });
            return newState;
        }
        case ADD_ROLE_TO_STORE: {
            const { roleData } = payload;
            let newState = produce(state, (draft) => {
                draft.roles[roleData.name] = roleData;
            });
            return newState;
        }
        case DELETE_ROLE_FROM_STORE: {
            const { roleName } = payload;
            let newState = produce(state, (draft) => {
                delete draft.roles[roleName];
            });
            return newState;
        }
        case LOAD_ROLE: {
            const { roleData, roleName } = payload;
            let newState = produce(state, (draft) => {
                draft.roles[roleName] = roleData;
            });
            return newState;
        }
        case LOAD_ROLES_TO_REVIEW: {
            const { rolesToReview } = payload;
            let newState = produce(state, (draft) => {
                draft.rolesToReview = rolesToReview;
            });
            return newState;
        }
        case ADD_MEMBER_TO_STORE: {
            const { member, category, collectionName } = payload;
            let newState = produce(state, (draft) => {
                if (category === 'role') {
                    if (
                        draft.roles[collectionName] &&
                        draft.roles[collectionName].roleMembers
                    ) {
                        draft.roles[collectionName].roleMembers[
                            member.memberName
                        ] = member;
                    } else {
                        draft.roles[collectionName].roleMembers = {
                            [member.memberName]: member,
                        };
                    }
                }
            });
            return newState;
        }
        case ADD_PENDING_MEMBER_TO_STORE: {
            const { member, category, collectionName } = payload;
            let newState = produce(state, (draft) => {
                if (category === 'role') {
                    if (
                        draft.roles[collectionName] &&
                        draft.roles[collectionName].rolePendingMembers
                    ) {
                        draft.roles[collectionName].rolePendingMembers[
                            member.memberName
                        ] = member;
                    } else {
                        draft.roles[collectionName].rolePendingMembers = {
                            [member.memberName]: member,
                        };
                    }
                }
            });
            return newState;
        }
        case DELETE_MEMBER_FROM_STORE: {
            const { memberName, category, collectionName } = payload;
            let newState = produce(state, (draft) => {
                if (category === 'role') {
                    if (
                        draft.roles[collectionName] &&
                        draft.roles[collectionName].roleMembers
                    ) {
                        delete draft.roles[collectionName].roleMembers[
                            memberName
                        ];
                    }
                }
            });
            return newState;
        }
        case DELETE_PENDING_MEMBER_FROM_STORE: {
            const { memberName, category, collectionName } = payload;
            let newState = produce(state, (draft) => {
                if (category === 'role') {
                    if (
                        draft.roles[collectionName] &&
                        draft.roles[collectionName].rolePendingMembers
                    ) {
                        delete draft.roles[collectionName].rolePendingMembers[
                            memberName
                        ];
                    }
                }
            });
            return newState;
        }
        case REVIEW_ROLE: {
            const { roleName, reviewedRole } = payload;
            const { roleMembers, auditLog, modified, lastReviewedDate } =
                reviewedRole;
            let newState = produce(state, (draft) => {
                draft.roles[roleName]
                    ? (draft.roles[roleName].roleMembers = roleMembers)
                    : (draft.roles[roleName] = { roleMembers });
                draft.roles[roleName].auditLog = auditLog;
                draft.roles[roleName].modified = modified;
                draft.roles[roleName].lastReviewedDate = lastReviewedDate;
            });
            return newState;
        }
        case UPDATE_TAGS_TO_STORE: {
            const { collectionName, collectionWithTags, category } = payload;
            let newState = state;
            if (category === 'role') {
                newState = produce(state, (draft) => {
                    draft.roles[collectionName]
                        ? (draft.roles[collectionName].tags =
                              collectionWithTags.tags)
                        : (draft.roles[collectionName] = collectionWithTags);
                });
            }
            return newState;
        }
        case UPDATE_SETTING_TO_STORE: {
            const { collectionName, collectionSettings, category } = payload;
            let newState = state;
            if (category === 'role') {
                newState = produce(state, (draft) => {
                    draft.roles[collectionName]
                        ? (draft.roles[collectionName] = {
                              ...draft.roles[collectionName],
                              ...collectionSettings,
                          })
                        : (draft.roles[collectionName] = {
                              ...collectionSettings,
                          });
                });
            }
            return newState;
        }
        case PROCESS_ROLE_PENDING_MEMBERS_TO_STORE: {
            const { domainName, member, roleName } = payload;
            let roleFullName = getFullCollectionName(
                domainName,
                roleName,
                'role'
            );
            let newState = state;
            if (state.roles && state.roles[roleFullName]) {
                newState = produce(state, (draft) => {
                    if (member.approved) {
                        if (member.pendingState === PENDING_STATE_ENUM.DELETE) {
                            delete draft.roles[roleFullName].roleMembers[
                                member.memberName
                            ];
                        } else {
                            draft.roles[roleFullName].roleMembers[
                                member.memberName
                            ] = member;
                        }
                    }
                    delete draft.roles[roleFullName].rolePendingMembers[
                        member.memberName
                    ];
                });
            }
            return newState;
        }
        case MARKS_ROLE_AS_NEED_REFRESH: {
            const { domainName, roleName, needRefresh } = payload;
            let roleFullName = getFullCollectionName(
                domainName,
                roleName,
                'role'
            );
            let newState = produce(state, (draft) => {
                draft.roles[roleFullName].needRefresh = needRefresh;
            });
            return newState;
        }
        case MAKE_ROLES_EXPIRES: {
            return produce(state, (draft) => {
                draft.expiry = getExpiredTime();
            });
        }
        case RETURN_ROLES:
        default:
            return state;
    }
};
