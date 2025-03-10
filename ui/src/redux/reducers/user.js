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
    ADD_ALL_USERS,
    LOAD_PENDING_MEMBERS,
    LOAD_RESOURCE_ACCESS_LIST,
    STORE_PENDING_GROUP,
    STORE_PENDING_ROLE,
} from '../actions/user';
import {
    PROCESS_GROUP_PENDING_MEMBERS_TO_STORE,
    PROCESS_ROLE_PENDING_MEMBERS_TO_STORE,
} from '../actions/domains';
import produce from 'immer';

export const user = (state = {}, action) => {
    const { type, payload } = action;
    switch (type) {
        case LOAD_PENDING_MEMBERS: {
            const { pendingMembers, expiry } = payload;
            return { ...state, pendingMembers, expiry };
        }
        case LOAD_RESOURCE_ACCESS_LIST: {
            const { resourceAccessList, expiry } = payload;
            return { ...state, resourceAccessList, expiry };
        }
        case PROCESS_ROLE_PENDING_MEMBERS_TO_STORE: {
            const { member, domainName, roleName } = payload;
            let newState = produce(state, (draft) => {
                if (
                    draft.pendingMembers[
                        domainName + member.memberName + roleName
                    ]
                ) {
                    delete draft.pendingMembers[
                        domainName + member.memberName + roleName
                    ];
                }
            });
            return newState;
        }
        case PROCESS_GROUP_PENDING_MEMBERS_TO_STORE: {
            const { member, domainName, groupName } = payload;
            let newState = produce(state, (draft) => {
                if (
                    draft.pendingMembers[
                        domainName + member.memberName + groupName
                    ]
                ) {
                    delete draft.pendingMembers[
                        domainName + member.memberName + groupName
                    ];
                }
            });
            return newState;
        }
        case ADD_ALL_USERS: {
            const { userList } = payload;
            return produce(state, (draft) => {
                draft.userList = userList;
            });
        }
        case STORE_PENDING_ROLE: {
            return produce(state, (draft) => {
                if (!draft.pendingMemberRoles) {
                    draft.pendingMemberRoles = {};
                }
                draft.pendingMemberRoles[
                    `${payload.domainName}:${payload.roleName}`
                ] = payload.role;
            });
        }
        case STORE_PENDING_GROUP: {
            return produce(state, (draft) => {
                if (!draft.pendingMemberGroups) {
                    draft.pendingMemberGroups = {};
                }
                draft.pendingMemberGroups[
                    `${payload.domainName}:${payload.groupName}`
                ] = payload.group;
            });
        }
        default:
            return state;
    }
};
