import { mapToList } from '../utils';

export const thunkSelectGroups = (state) => {
    return state.groups.groups ? state.groups.groups : {};
};

export const thunkSelectGroup = (state, groupName) => {
    return selectGroup(state, groupName);
};

export const thunkSelectGroupMembers = (state, groupName) => {
    return state.groups.groups && state.groups.groups[groupName]
        ? state.groups.groups[groupName].groupMembers
        : {};
};

export const thunkSelectGroupHistory = (state, groupName) => {
    return selectGroupHistory(state, groupName);
};

export const thunkSelectGroupRoleMembers = (state) => {
    return selectGroupRoleMembers(state);
};

export const selectGroups = (state) => {
    return state.groups.groups ? mapToList(state.groups.groups) : [];
};

export const selectGroup = (state, groupName) => {
    return state.groups.groups ? state.groups.groups[groupName] : {};
};

export const selectGroupMembers = (state, groupName) => {
    return state.groups.groups && state.groups.groups[groupName]
        ? mapToList(state.groups.groups[groupName].groupMembers)
        : [];
};

export const selectGroupHistory = (state, groupName) => {
    return state.groups.groups &&
        state.groups.groups[groupName] &&
        state.groups.groups[groupName].auditLog
        ? state.groups.groups[groupName].auditLog
        : [];
};

export const selectGroupRoleMembers = (state) => {
    return state.groups.roleMembers ? state.groups.roleMembers : {};
};

export const selectGroupTags = (state, groupName) => {
    return state.groups.groups &&
        state.groups.groups[groupName] &&
        state.groups.groups[groupName].tags
        ? state.groups.groups[groupName].tags
        : {};
};
