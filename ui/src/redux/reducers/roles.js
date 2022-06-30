import {
    ADD_ROLE_TAGS_TO_STORE,
    ADD_ROLE_TO_STORE,
    DELETE_ROLE_FROM_STORE,
    LOAD_ROLE,
    LOAD_ROLE_USERS,
    LOAD_ROLES,
    RETURN_ROLES,
    REVIEW_ROLE,
} from '../actions/roles';
import {
    DELETE_MEMBER_TO_STORE,
    ADD_MEMBER_TO_STORE,
} from '../actions/collections';

export const roles = (state = {}, action) => {
    const { type, payload } = action;
    switch (type) {
        case LOAD_ROLES: {
            const { roles, domainName, expiry } = payload;
            console.log('in LOAD_ROLES', roles);
            return { domainName: domainName, expiry: expiry, roles: roles };
        }
        case ADD_ROLE_TO_STORE: {
            const { roleName, roleData } = payload;
            let newState = { ...state };
            newState.roles[roleName] = roleData;
            return { ...newState };
        }
        case DELETE_ROLE_FROM_STORE: {
            const { roleName } = payload;
            let newState = { ...state };
            delete newState.roles[roleName];
            return { ...newState };
        }
        case LOAD_ROLE: {
            const { roleData, roleName } = payload;
            let newState = { ...state };
            newState.roles[roleName] = roleData;
            console.log('in LOAD_ROLE', roleData);
            return { ...newState };
        }
        case LOAD_ROLE_USERS: {
            const { roleUsers } = payload;
            let newState = { ...state };
            newState.roleUsers = roleUsers;
            return { ...newState };
        }
        case ADD_MEMBER_TO_STORE: {
            const { member, category, collectionName } = payload;
            let newState = { ...state };
            if (category === 'role') {
                let role = newState.roles[collectionName];
                if (role && role.roleMembers) {
                    role.roleMembers[member.memberName] = member;
                }
            }
            return { ...newState };
        }
        case DELETE_MEMBER_TO_STORE: {
            const { memberName, category, collectionName } = payload;
            let newState = { ...state };
            if (category === 'role') {
                let role = newState.roles[collectionName];
                if (role && role.roleMembers) {
                    delete role.roleMembers[memberName];
                }
            }
            return { ...newState };
        }
        case REVIEW_ROLE: {
            const { roleName, roleMembers } = payload;
            let newState = { ...state };
            let role = newState.roles[roleName];
            if (role && role.roleMembers) {
                role.roleMembers = roleMembers;
            }
            return { ...newState };
        }
        case ADD_ROLE_TAGS_TO_STORE: {
            const { roleName, tags } = payload;
            let newState = { ...state };
            let role = newState.roles[roleName];
            if (role) {
                role.tags = tags;
            }
            return { ...newState };
        }
        case RETURN_ROLES:
            return state;
        default:
            return state;
    }
};
