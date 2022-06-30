export const LOAD_ROLES = 'LOAD_ROLES';
export const loadRoles = (roles, domainName, expiry) => ({
    type: LOAD_ROLES,
    payload: { roles: roles, domainName: domainName, expiry: expiry },
});

export const RETURN_ROLES = 'RETURN_ROLES';
export const returnRoles = () => ({
    type: RETURN_ROLES,
});

export const ADD_ROLE_TO_STORE = 'ADD_ROLE_TO_STORE';
export const addRoleToStore = (roleName, roleData) => ({
    type: ADD_ROLE_TO_STORE,
    payload: {
        roleName: roleName,
        roleData: roleData,
    },
});

export const DELETE_ROLE_FROM_STORE = 'DELETE_ROLE_FROM_STORE';
export const deleteRoleFromStore = (roleName) => ({
    type: DELETE_ROLE_FROM_STORE,
    payload: {
        roleName: roleName,
    },
});
export const LOAD_ROLE = 'LOAD_ROLE';
export const loadRole = (roleData, roleName) => ({
    type: LOAD_ROLE,
    payload: {
        roleData: roleData,
        roleName: roleName,
    },
});
export const LOAD_ROLE_USERS = 'LOAD_ROLE_USERS';
export const loadRoleUsers = (roleUsers) => ({
    type: LOAD_ROLE_USERS,
    payload: {
        roleUsers,
    },
});

export const REVIEW_ROLE = 'REVIEW_ROLE';
export const reviewRole = (roleName, roleMembers) => ({
    type: REVIEW_ROLE,
    payload: {
        roleName,
        roleMembers,
    },
});

export const ADD_ROLE_TAGS_TO_STORE = 'ADD_ROLE_TAGS_TO_STORE';
export const addRoleTagsToStore = (roleName, tags) => ({
    type: ADD_ROLE_TAGS_TO_STORE,
    payload: {
        roleName,
        tags,
    },
});
