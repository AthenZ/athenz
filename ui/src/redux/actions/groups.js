export const LOAD_GROUPS = 'LOAD_GROUPS';
export const loadGroups = (groups, domainName, expiry) => ({
    type: LOAD_GROUPS,
    payload: {
        groups: groups,
        domainName: domainName,
        expiry: expiry,
    },
});

export const RETURN_GROUPS = 'RETURN_GROUPS';
export const returnGroups = () => ({
    type: RETURN_GROUPS,
});

export const ADD_GROUP_TO_STORE = 'ADD_GROUP_TO_STORE';
export const addGroupToStore = (groupName, groupData) => ({
    type: ADD_GROUP_TO_STORE,
    payload: {
        groupName: groupName,
        groupData: groupData,
    },
});

export const DELETE_GROUP_FROM_STORE = 'DELETE_GROUP_FROM_STORE';
export const deleteGroupFromStore = (groupName) => ({
    type: DELETE_GROUP_FROM_STORE,
    payload: {
        groupName: groupName,
    },
});

export const LOAD_GROUP = 'LOAD_GROUP';
export const loadGroup = (groupData, groupName) => ({
    type: LOAD_GROUP,
    payload: {
        groupData: groupData,
        groupName: groupName,
    },
});

export const LOAD_GROUP_ROLE_MEMBERS = 'LOAD_GROUP_ROLE_MEMBERS';
export const loadGroupRoleMembers = (groupName, roleMembers) => ({
    type: LOAD_GROUP_ROLE_MEMBERS,
    payload: {
        groupName,
        roleMembers,
    },
});

export const RETURN_ROLE_MEMBERS = 'RETURN_ROLE_MEMBERS';
export const returnRoleMembers = () => ({
    type: RETURN_ROLE_MEMBERS,
});

export const REVIEW_GROUP = 'REVIEW_GROUP';
export const reviewGroupToStore = (groupName, groupMembers) => ({
    type: REVIEW_GROUP,
    payload: {
        groupName,
        groupMembers,
    },
});
