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
export const reviewRoleToStore = (roleName, roleMembers) => ({
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

export const UPDATE_ROLE_SETTING_TO_STORE = 'UPDATE_ROLE_SETTING_TO_STORE';
export const updateRoleSettings = (roleName, roleSetting) => ({
    type: UPDATE_ROLE_SETTING_TO_STORE,
    payload: {
        roleName,
        roleSetting,
    },
});

export const ADD_MEMBER_TO_ROLES_TO_STORE = 'ADD_MEMBER_TO_ROLES_TO_STORE';
export const addMemberToRolesToStore = (member, rolesList) => ({
    type: ADD_MEMBER_TO_ROLES_TO_STORE,
    payload: {
        member,
        rolesList,
    },
});

export const DELETE_ROLE_USERS_MEMBER = 'DELETE_ROLE_USERS_MEMBER';
export const deleteRoleUsersMember = (memberName, roleName) => ({
    type: DELETE_ROLE_USERS_MEMBER,
    payload: {
        memberName,
        roleName,
    },
});
