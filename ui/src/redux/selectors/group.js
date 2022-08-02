import { getFullName, mapToList } from '../utils';
import { groupDelimiter } from '../config';

export const thunkSelectGroups = (state) => {
    return state.groups.groups ? state.groups.groups : {};
};

export const thunkSelectGroup = (state, domainName, groupName) => {
    return selectGroup(state, domainName, groupName);
};

export const selectGroups = (state) => {
    return state.groups.groups ? mapToList(state.groups.groups) : [];
};

export const selectGroup = (state, domainName, groupName) => {
    return state.groups.groups &&
        state.groups.groups[getFullName(domainName, groupDelimiter, groupName)]
        ? state.groups.groups[
              getFullName(domainName, groupDelimiter, groupName)
          ]
        : {};
};

export const selectGroupMembers = (state, domainName, groupName) => {
    return state.groups.groups &&
        state.groups.groups[getFullName(domainName, groupDelimiter, groupName)]
        ? mapToList(
              state.groups.groups[
                  getFullName(domainName, groupDelimiter, groupName)
              ].groupMembers
          )
        : [];
};

export const selectGroupHistory = (state, domainName, groupName) => {
    return state.groups.groups &&
        state.groups.groups[
            getFullName(domainName, groupDelimiter, groupName)
        ] &&
        state.groups.groups[getFullName(domainName, groupDelimiter, groupName)]
            .auditLog
        ? state.groups.groups[
              getFullName(domainName, groupDelimiter, groupName)
          ].auditLog
        : [];
};

export const selectGroupRoleMembers = (state, domainName, groupName) => {
    return state.groups.groups &&
        state.groups.groups[
            getFullName(domainName, groupDelimiter, groupName)
        ] &&
        state.groups.groups[getFullName(domainName, groupDelimiter, groupName)]
            .roleMembers
        ? state.groups.groups[
              getFullName(domainName, groupDelimiter, groupName)
          ].roleMembers
        : [];
};

export const selectGroupTags = (state, domainName, groupName) => {
    return state.groups.groups &&
        state.groups.groups[
            getFullName(domainName, groupDelimiter, groupName)
        ] &&
        state.groups.groups[getFullName(domainName, groupDelimiter, groupName)]
            .tags
        ? state.groups.groups[
              getFullName(domainName, groupDelimiter, groupName)
          ].tags
        : {};
};
