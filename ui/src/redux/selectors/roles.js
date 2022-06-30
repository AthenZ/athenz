import { mapToList } from '../utils';

export const thunkSelectRoles = (state) => {
    return state.roles.roles ? state.roles.roles : {};
};

export const thunkSelectRoleUsers = (state) => {
    return selectRoleUsers(state);
};

export const thunkSelectRole = (state, roleName) => {
    return state.roles.roles && state.roles.roles[roleName]
        ? state.roles.roles[roleName]
        : {};
};

export const selectRoles = (state) => {
    return state.roles.roles ? mapToList(state.roles.roles) : [];
};

export const selectRoleUsers = (state) => {
    return state.roles.roleUsers
        ? state.roles.roleUsers
        : {
              expand: {},
              contents: {},
              expandArray: {},
              fullNames: {},
              members: [],
          };
};

export const selectRole = (state, roleName) => {
    return state.roles.roles && state.roles.roles[roleName]
        ? state.roles.roles[roleName]
        : {};
};

export const selectRoleMembers = (state, roleName) => {
    return state.roles.roles &&
        state.roles.roles[roleName] &&
        state.roles.roles[roleName].roleMembers
        ? mapToList(state.roles.roles[roleName].roleMembers)
        : [];
};

export const selectRoleTags = (state, roleName) => {
    return state.roles.roles &&
        state.roles.roles[roleName] &&
        state.roles.roles[roleName].tags
        ? state.roles.roles[roleName].tags
        : {};
};
