import {
    ADD_MEMBER_TO_ROLES_TO_STORE,
    ADD_ROLE_TAGS_TO_STORE,
    ADD_ROLE_TO_STORE,
    DELETE_ROLE_FROM_STORE,
    DELETE_ROLE_USERS_MEMBER,
    LOAD_ROLE,
    LOAD_ROLE_USERS,
    LOAD_ROLES,
    RETURN_ROLES,
    REVIEW_ROLE,
    UPDATE_ROLE_SETTING_TO_STORE,
} from '../actions/roles';
import {
    ADD_MEMBER_TO_STORE,
    DELETE_MEMBER_FROM_STORE,
} from '../actions/collections';
import produce from 'immer';
import NameUtils from '../../components/utils/NameUtils';
import { PROCESS_PENDING_MEMBERS_TO_STORE } from '../actions/domains';
import { getFullName } from '../utils';
import { roleDelimiter } from '../config';

// TODO roy - should i prevent here mistake or do i want to get errors in places which i dont sopuse to be in -
// TODO roy - let say i need to add tag but the role doesnt exist - i should get error in that case or handle it in here?
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
            console.log('LOAD_ROLES', newState);
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
            console.log('LOAD_ROLE', roleData);
            let newState = produce(state, (draft) => {
                draft.roles[roleName] = roleData;
            });
            return newState;
        }
        case LOAD_ROLE_USERS: {
            const { roleUsers } = payload;
            let newState = produce(state, (draft) => {
                draft.roleUsers = roleUsers;
            });
            console.log('LOAD_ROLE_USERS', newState.roleUsers);
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
            console.log('add member to store: ', member, newState);
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
            console.log('DELETE_MEMBER_FROM_STORE', newState);
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
        case ADD_ROLE_TAGS_TO_STORE: {
            const { roleName, tags } = payload;
            let newState = produce(state, (draft) => {
                draft.roles[roleName]
                    ? (draft.roles[roleName].tags = tags)
                    : (draft.roles[roleName] = { tags });
            });
            return newState;
        }
        case UPDATE_ROLE_SETTING_TO_STORE: {
            const { roleName, roleSetting } = payload;
            let newState = produce(state, (draft) => {
                draft.roles[roleName]
                    ? (draft.roles[roleName] = {
                          ...draft.roles[roleName],
                          ...roleSetting,
                      })
                    : (draft.roles[roleName] = { ...roleSetting });
            });
            console.log('in UPDATE_ROLE_SETTING_TO_STORE', newState);
            return newState;
        }
        case ADD_MEMBER_TO_ROLES_TO_STORE: {
            const { rolesList, member } = payload;
            let newState = produce(state, (draft) => {
                rolesList.forEach((roleName) => {
                    if (
                        draft.roles[roleName] &&
                        draft.roles[roleName].roleMembers
                    ) {
                        draft.roles[roleName].roleMembers[member.memberName] =
                            member;
                    } else {
                        draft.roles[roleName] = {
                            roleMembers: { [member.memberName]: member },
                        };
                    }
                });
            });
            console.log('in ADD_MEMBER_TO_ROLES_TO_STORE', newState);
            return newState;
        }
        case DELETE_ROLE_USERS_MEMBER: {
            const { roleName, memberName } = payload;
            let newState = { ...state };
            if (newState.roleUsers.expiry) {
                newState.roleUsers.expand[memberName].memberRoles =
                    newState.roleUsers.expand[memberName].memberRoles.filter(
                        (role) => role.roleName !== roleName
                    );
                x;
                if (
                    newState.roleUsers.expand[memberName].memberRoles.length ===
                    0
                ) {
                    newState.roleUsers.members =
                        newState.roleUsers.members.filter(
                            (member) => member.memberName !== memberName
                        );
                }
                console.log('in DELETE_ROLE_USERS_MEMBER', newState.roleUsers);
            }
            return newState;
        }
        case PROCESS_PENDING_MEMBERS_TO_STORE: {
            const { domainName, member, roleName } = payload;
            let newState = state;
            if (
                state.roles &&
                state.roles[getFullName(domainName, roleDelimiter, roleName)]
            ) {
                newState = produce(state, (draft) => {
                    if (member.approved) {
                        draft.roles[
                            getFullName(domainName, roleDelimiter, roleName)
                        ].roleMembers[member.memberName].approved = true;
                    } else {
                        delete draft.roles[
                            getFullName(domainName, roleDelimiter, roleName)
                        ].roleMembers[member.memberName];
                    }
                });
            }
            return newState;
        }
        case RETURN_ROLES:
            return state;
        default:
            return state;
    }
};
