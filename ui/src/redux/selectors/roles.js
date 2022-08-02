import { getFullName, mapToList } from '../utils';
import { roleDelimiter } from '../config';

export const thunkSelectRoles = (state) => {
    return state.roles.roles ? state.roles.roles : {};
};

export const thunkSelectRole = (state, domainName, roleName) => {
    return selectRole(state, domainName, roleName);
};

export const thunkSelectRoleMembers = (state, domainName, roleName) => {
    return state.roles.roles &&
        state.roles.roles[getFullName(domainName, roleDelimiter, roleName)] &&
        state.roles.roles[getFullName(domainName, roleDelimiter, roleName)]
            .roleMembers
        ? state.roles.roles[getFullName(domainName, roleDelimiter, roleName)]
              .roleMembers
        : [];
};

export const selectRoles = (state) => {
    return state.roles.roles ? mapToList(state.roles.roles) : [];
};

const buildUserMapFromRoles = (roles) => {
    let userMap = {};
    for (const [roleName, role] of Object.entries(roles)) {
        for (let [memberName, member] of Object.entries(role.roleMembers)) {
            if (userMap[memberName]) {
                userMap[memberName].memberRoles.push({
                    roleName: roleName,
                    expiration: member.expiration,
                });
            } else {
                userMap[member.memberName] = { ...member };
                userMap[member.memberName].memberRoles = [
                    {
                        roleName: roleName,
                        expiration: member.expiration,
                    },
                ];
            }
        }
    }
    return userMap;
};

export const selectRoleUsers = (state) => {
    return state.roles.roles
        ? mapToList(buildUserMapFromRoles(state.roles.roles))
        : [];
};

export const selectRole = (state, domainName, roleName) => {
    return state.roles.roles &&
        state.roles.roles[getFullName(domainName, roleDelimiter, roleName)]
        ? state.roles.roles[getFullName(domainName, roleDelimiter, roleName)]
        : {};
};

export const selectRoleMembers = (state, domainName, roleName) => {
    return state.roles.roles &&
        state.roles.roles[getFullName(domainName, roleDelimiter, roleName)] &&
        state.roles.roles[getFullName(domainName, roleDelimiter, roleName)]
            .roleMembers
        ? mapToList(
              state.roles.roles[
                  getFullName(domainName, roleDelimiter, roleName)
              ].roleMembers
          )
        : [];
};

export const selectRoleTags = (state, domainName, roleName) => {
    return state.roles.roles &&
        state.roles.roles[getFullName(domainName, roleDelimiter, roleName)] &&
        state.roles.roles[getFullName(domainName, roleDelimiter, roleName)].tags
        ? state.roles.roles[getFullName(domainName, roleDelimiter, roleName)]
              .tags
        : {};
};

export const selectRoleHistory = (state, domainName, roleName) => {
    return state.roles.roles &&
        state.roles.roles[getFullName(domainName, roleDelimiter, roleName)] &&
        state.roles.roles[getFullName(domainName, roleDelimiter, roleName)]
            .auditLog
        ? state.roles.roles[getFullName(domainName, roleDelimiter, roleName)]
              .auditLog
        : [];
};
