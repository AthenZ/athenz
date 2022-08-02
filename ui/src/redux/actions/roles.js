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
export const REVIEW_ROLE = 'REVIEW_ROLE';
export const reviewRoleToStore = (roleName, roleMembers) => ({
    type: REVIEW_ROLE,
    payload: {
        roleName,
        roleMembers,
    },
});

export const MAKE_ROLES_EXPIRES = 'MAKE_ROLES_EXPIRES';
export const makeRolesExpires = () => ({
    type: MAKE_ROLES_EXPIRES,
});
