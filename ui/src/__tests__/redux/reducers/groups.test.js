import { _ } from 'lodash';
import {
    domainName,
    expiry,
    singleStoreGroup,
    storeGroups,
} from '../../config/config.test';
import {
    ADD_GROUP_TO_STORE,
    DELETE_GROUP_FROM_STORE,
    LOAD_GROUP,
    LOAD_GROUP_ROLE_MEMBERS,
    LOAD_GROUPS,
} from '../../../redux/actions/groups';
import { groups } from '../../../redux/reducers/groups';
import AppUtils from '../../../components/utils/AppUtils';
import {
    ADD_MEMBER_TO_STORE,
    DELETE_MEMBER_FROM_STORE,
    UPDATE_SETTING_TO_STORE,
    UPDATE_TAGS_TO_STORE,
} from '../../../redux/actions/collections';

let groupRoleMembers = {
    memberName: 'dom:group.group1',
    memberRoles: [{ roleName: 'role1', domainName: 'dom' }],
    prefix: ['dom'],
};

let member = {
    memberName: 'user.user2',
    expiration: '',
    reviewReminder: '',
    approved: true,
};

let groupSetting = {
    memberExpiryDays: '100',
    reviewEnabled: false,
    selfServe: false,
    serviceExpiryDays: '',
    userAuthorityExpiration: '',
    userAuthorityFilter: '',
};

describe('Groups Reducer', () => {
    it('should load the groups into the store', () => {
        const initialState = {};
        const action = {
            type: LOAD_GROUPS,
            payload: {
                groups: storeGroups,
                domainName: domainName,
                expiry: expiry,
            },
        };
        const expectedState = {
            groups: storeGroups,
            domainName: domainName,
            expiry: expiry,
        };
        const newState = groups(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should load group into the store', () => {
        const initialState = {
            groups: {},
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: LOAD_GROUP,
            payload: {
                groupData: singleStoreGroup,
                groupName: 'dom:group.singlegroup',
            },
        };
        const expectedState = {
            groups: { ['dom:group.singlegroup']: singleStoreGroup },
            domainName: domainName,
            expiry: expiry,
        };
        const newState = groups(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should add singlegroup into the store', () => {
        const initialState = {
            groups: storeGroups,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: ADD_GROUP_TO_STORE,
            payload: {
                groupData: singleStoreGroup,
                groupName: 'dom:group.singlegroup',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.groups['dom:group.singlegroup'] = singleStoreGroup;
        const newState = groups(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should delete group1 from the store', () => {
        const initialState = {
            groups: storeGroups,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: DELETE_GROUP_FROM_STORE,
            payload: {
                groupName: 'dom:group.group1',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        delete expectedState.groups['dom:group.group1'];
        const newState = groups(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should delete and edit tags from expiration', () => {
        const initialState = {
            groups: storeGroups,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: UPDATE_TAGS_TO_STORE,
            payload: {
                collectionName: 'dom:group.expiration',
                collectionTags: { tag: { list: ['tag3', 'tag2'] } },
                category: 'group',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.groups['dom:group.expiration'].tags = {
            tag: { list: ['tag3', 'tag2'] },
        };
        const newState = groups(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should add tags to group1 to the store', () => {
        const initialState = {
            groups: storeGroups,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: UPDATE_TAGS_TO_STORE,
            payload: {
                collectionName: 'dom:group.group1',
                collectionTags: { tag: { list: ['tag1', 'tag2'] } },
                category: 'group',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.groups['dom:group.group1'].tags = {
            tag: { list: ['tag1', 'tag2'] },
        };
        const newState = groups(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should insert to the store a member to group1', () => {
        const initialState = {
            groups: storeGroups,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: ADD_MEMBER_TO_STORE,
            payload: {
                collectionName: 'dom:group.group1',
                category: 'group',
                member,
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.groups['dom:group.group1'].groupMembers['user.user2'] =
            member;
        const newState = groups(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should delete from the store a member from group1', () => {
        const initialState = {
            groups: storeGroups,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: DELETE_MEMBER_FROM_STORE,
            payload: {
                collectionName: 'dom:group.group1',
                category: 'group',
                memberName: 'user.user4',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        delete expectedState.groups['dom:group.group1'].groupMembers[
            'user.user4'
        ];
        const newState = groups(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should change group settings of group1 in the store', () => {
        const initialState = {
            groups: storeGroups,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: UPDATE_SETTING_TO_STORE,
            payload: {
                collectionName: 'dom:group.group1',
                category: 'group',
                collectionSettings: groupSetting,
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.groups['dom:group.group1'] = {
            ...expectedState.groups['dom:group.group1'],
            ...groupSetting,
        };
        const newState = groups(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should load the group role members into the store for group1', () => {
        const initialState = {
            groups: storeGroups,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: LOAD_GROUP_ROLE_MEMBERS,
            payload: {
                groupName: 'dom:group.group1',
                roleMembers: groupRoleMembers,
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.groups['dom:group.group1'].roleMembers = groupRoleMembers;
        const newState = groups(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
});
