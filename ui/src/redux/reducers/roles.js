import {
    ADD_ROLE_TO_STORE,
    DELETE_ROLE_FROM_STORE,
    LOAD_ROLE,
    LOAD_ROLES,
    MAKE_ROLES_EXPIRES,
    RETURN_ROLES,
    REVIEW_ROLE,
} from '../actions/roles';
import {
    ADD_MEMBER_TO_STORE,
    DELETE_MEMBER_FROM_STORE,
    UPDATE_SETTING_TO_STORE,
    UPDATE_TAGS_TO_STORE,
} from '../actions/collections';
import produce from 'immer';
import { PROCESS_PENDING_MEMBERS_TO_STORE } from '../actions/domains';
import { getExpiredTime } from '../utils';


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
            const { roleName, roleData } = payload;
            let newState = produce(state, (draft) => {
                draft.roles[roleName] = roleData;
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
        case REVIEW_ROLE: {
            const { roleName, roleMembers } = payload;
            let newState = produce(state, (draft) => {
                draft.roles[roleName]
                    ? (draft.roles[roleName].roleMembers = roleMembers)
                    : (draft.roles[roleName] = { roleMembers });
            });
            return newState;
        }
        case UPDATE_TAGS_TO_STORE: {
            const { collectionName, collectionTags, category } = payload;
            let newState = state;
            if (category === 'role') {
                newState = produce(state, (draft) => {
                    draft.roles[collectionName]
                        ? (draft.roles[collectionName].tags = collectionTags)
                        : (draft.roles[collectionName] = { collectionTags });
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
        case PROCESS_PENDING_MEMBERS_TO_STORE: {
            const { member, roleName } = payload;
            let newState = state;
            if (state.roles && state.roles[roleName]) {
                newState = produce(state, (draft) => {
                    if (member.approved) {
                        draft.roles[roleName].roleMembers[
                            member.memberName
                        ].approved = true;
                    } else {
                        delete draft.roles[roleName].roleMembers[
                            member.memberName
                        ];
                    }
                });
            }
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
