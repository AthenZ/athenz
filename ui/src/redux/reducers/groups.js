import {
    ADD_GROUP_TAGS_TO_STORE,
    ADD_GROUP_TO_STORE,
    DELETE_GROUP_FROM_STORE,
    LOAD_GROUP,
    LOAD_GROUPS,
    LOAD_GROUP_ROLE_MEMBERS,
    RETURN_GROUPS,
    REVIEW_GROUP,
    UPDATE_GROUP_SETTING_TO_STORE,
} from '../actions/groups';
import {
    ADD_MEMBER_TO_STORE,
    DELETE_MEMBER_FROM_STORE,
} from '../actions/collections';
import produce from 'immer';
import { isExpired } from '../utils';

export const groups = (state = {}, action) => {
    const { type, payload } = action;
    switch (type) {
        // we load the groups in that way because and we dont want to lose the audit log which we gets in getGroup api call
        case LOAD_GROUPS: {
            const { groups, domainName, expiry } = payload;
            let newState = produce(state, (draft) => {
                draft.domainName = domainName;
                draft.expiry = expiry;
                if (draft.groups) {
                    for (const [groupName, group] of Object.entries(groups)) {
                        if (
                            !(groupName in draft.groups) ||
                            isExpired(draft.groups[groupName].expiry)
                        ) {
                            draft[groupName] = group;
                        }
                    }
                } else {
                    draft.groups = groups;
                }
            });
            console.log('LOAD_GROUPS', groups);
            return newState;
        }
        case ADD_GROUP_TO_STORE: {
            const { groupName, groupData } = payload;
            let newState = produce(state, (draft) => {
                draft.groups[groupName] = groupData;
            });
            console.log('ADD_GROUP_TO_STORE', newState);
            return newState;
        }
        case DELETE_GROUP_FROM_STORE: {
            const { groupName } = payload;
            let newState = produce(state, (draft) => {
                delete draft.groups[groupName];
            });
            console.log('in DELETE_GROUP_FROM_STORE', newState);
            return newState;
        }
        case ADD_MEMBER_TO_STORE: {
            const { member, category, collectionName } = payload;
            let newState = produce(state, (draft) => {
                if (category === 'group') {
                    if (
                        draft.groups[collectionName] &&
                        draft.groups[collectionName].groupMembers
                    ) {
                        draft.groups[collectionName].groupMembers[
                            member.memberName
                        ] = member;
                    } else {
                        draft.groups[collectionName] = {
                            groupMembers: { [member.memberName]: member },
                        };
                    }
                }
            });
            return newState;
        }
        case DELETE_MEMBER_FROM_STORE: {
            const { memberName, category, collectionName } = payload;
            let newState = produce(state, (draft) => {
                if (category === 'group') {
                    if (
                        draft.groups[collectionName] &&
                        draft.groups[collectionName].groupMembers
                    ) {
                        delete draft.groups[collectionName].groupMembers[
                            memberName
                        ];
                    }
                }
            });
            return newState;
        }
        case ADD_GROUP_TAGS_TO_STORE: {
            const { groupName, tags } = payload;
            let newState = produce(state, (draft) => {
                if (draft.groups[groupName]) {
                    draft.groups[groupName].tags = tags;
                }
            });
            return newState;
        }
        case LOAD_GROUP: {
            const { groupData, groupName } = payload;
            console.log('LOAD_GROUP', groupData);
            let newState = produce(state, (draft) => {
                draft.groups[groupName] = groupData;
            });
            return newState;
        }
        case UPDATE_GROUP_SETTING_TO_STORE: {
            const { groupName, groupSetting } = payload;
            let newState = produce(state, (draft) => {
                draft.groups[groupName] = {
                    ...draft.groups[groupName],
                    ...groupSetting,
                };
            });
            return newState;
        }
        case REVIEW_GROUP: {
            const { groupName, groupMembers } = payload;
            let newState = produce(state, (draft) => {
                draft.groups[groupName]
                    ? (draft.groups[groupName].groupMembers = groupMembers)
                    : (draft.groups[groupName] = { groupMembers });
            });
            return newState;
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
