import {
    ADD_GROUP_TAGS_TO_STORE,
    ADD_GROUP_TO_STORE,
    DELETE_GROUP_FROM_STORE,
    LOAD_GROUP,
    LOAD_GROUPS,
    LOAD_GROUP_ROLE_MEMBERS,
    RETURN_GROUP,
    RETURN_GROUPS,
    REVIEW_GROUP,
    UPDATE_GROUP_SETTING_TO_STORE,
} from '../actions/groups';
import { selectGroup } from '../selectors';
import {
    ADD_MEMBER_TO_STORE,
    DELETE_MEMBER_TO_STORE,
} from '../actions/collections';

export const groups = (state = {}, action) => {
    const { type, payload } = action;
    switch (type) {
        // we do it like this because we load groups every time it expiry
        // and we dont want to lose any get group data calls.
        case LOAD_GROUPS: {
            const { groups, domainName, expiry } = payload;
            let newState = { ...state };
            newState.expiry = expiry;
            newState.domainName = domainName;
            if (newState.groups) {
                for (const [groupName, group] of Object.entries(groups)) {
                    if (!(groupName in newState.groups)) {
                        newState[groupName] = group;
                    }
                }
            } else {
                newState.groups = groups;
            }
            console.log('LOAD_GROUPS', newState);
            return { ...newState };
        }
        case ADD_GROUP_TO_STORE: {
            let newState = { ...state };
            const { groupName, groupData } = payload;
            newState.groups[groupName] = groupData;
            console.log('ADD_GROUP_TO_STORE', groupData);
            return { ...newState };
        }
        case DELETE_GROUP_FROM_STORE: {
            const { groupName } = payload;
            let newState = { ...state };
            delete newState.groups[groupName];
            console.log('in DELETE_GROUP_FROM_STORE', newState);
            return { ...newState };
        }
        case ADD_MEMBER_TO_STORE: {
            const { member, category, collectionName } = payload;
            let newState = { ...state };
            if (category === 'group') {
                let group = newState.groups[collectionName];
                if (group && group.groupMembers) {
                    group.groupMembers[member.memberName] = member;
                }
            }
            return { ...newState };
        }
        case DELETE_MEMBER_TO_STORE: {
            const { memberName, category, collectionName } = payload;
            let newState = { ...state };
            if (category === 'group') {
                let group = newState.groups[collectionName];
                if (group && group.groupMembers) {
                    delete group.groupMembers[memberName];
                }
            }
            return { ...newState };
        }
        case ADD_GROUP_TAGS_TO_STORE: {
            const { groupName, tags } = payload;
            let newState = { ...state };
            let group = newState.groups[groupName];
            if (group) {
                group.tags = tags;
            }
            return { ...newState };
        }
        case LOAD_GROUP: {
            const { groupData, groupName } = payload;
            let newGroups = { ...state.groups };
            newGroups[groupName] = groupData;
            console.log('LOAD_GROUP', groupData);
            return { ...state, groups: newGroups };
        }
        case UPDATE_GROUP_SETTING_TO_STORE: {
            const { groupName, groupSetting } = payload;
            let newState = { ...state };
            let group = newState.groups[groupName];
            group = { ...group, ...groupSetting };
            newState.groups[groupName] = group;
            return { ...newState };
        }
        case REVIEW_GROUP: {
            const { groupName, groupMembers } = payload;
            let newState = { ...state };
            let group = newState.groups[groupName];
            if (group && group.groupMembers) {
                group.groupMembers = groupMembers;
            }
            console.log('REVIEW_GROUP', group, newState);
            return { ...newState };
        }
        case LOAD_GROUP_ROLE_MEMBERS: {
            const { roleMembers } = payload;
            return { ...state, roleMembers };
        }
        case RETURN_GROUPS:
            return state;
        default:
            return state;
    }
};
