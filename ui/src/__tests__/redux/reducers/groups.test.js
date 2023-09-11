/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import { _ } from 'lodash';
import { domainName, expiry, modified } from '../../config/config.test';

import {
    singleStoreGroup,
    configStoreGroups,
    groupAuditLog,
    configStoreGroupsWithPendingMembers,
} from '../config/group.test';
import {
    ADD_GROUP_TO_STORE,
    DELETE_GROUP_FROM_STORE,
    LOAD_GROUP,
    LOAD_GROUP_ROLE_MEMBERS,
    LOAD_GROUPS,
    REVIEW_GROUP,
} from '../../../redux/actions/groups';
import { groups } from '../../../redux/reducers/groups';
import AppUtils from '../../../components/utils/AppUtils';
import {
    ADD_MEMBER_TO_STORE,
    ADD_PENDING_MEMBER_TO_STORE,
    DELETE_MEMBER_FROM_STORE,
    DELETE_PENDING_MEMBER_FROM_STORE,
    UPDATE_SETTING_TO_STORE,
    UPDATE_TAGS_TO_STORE,
} from '../../../redux/actions/collections';
import { configStoreRoles } from '../config/role.test';
import {
    PROCESS_GROUP_PENDING_MEMBERS_TO_STORE,
    PROCESS_ROLE_PENDING_MEMBERS_TO_STORE,
} from '../../../redux/actions/domains';
import { roles } from '../../../redux/reducers/roles';
import { PENDING_STATE_ENUM } from '../../../components/constants/constants';

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
                groups: configStoreGroups,
                domainName: domainName,
                expiry: expiry,
            },
        };
        const expectedState = {
            groups: configStoreGroups,
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
            groups: configStoreGroups,
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
            groups: configStoreGroups,
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
            groups: configStoreGroups,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: UPDATE_TAGS_TO_STORE,
            payload: {
                collectionName: 'dom:group.expiration',
                collectionWithTags: {
                    ...configStoreGroups['dom:group.expiration'],
                    tags: { key1: ['tag3', 'tag2'] },
                },
                category: 'group',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.groups['dom:group.expiration'].tags = {
            key1: ['tag3', 'tag2'],
        };
        const newState = groups(initialState, action);
        expect(newState).toEqual(expectedState);
    });
    it('should add tags to group1 to the store', () => {
        const initialState = {
            groups: configStoreGroups,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: UPDATE_TAGS_TO_STORE,
            payload: {
                collectionName: 'dom:group.group1',
                collectionWithTags: {
                    ...configStoreGroups['dom:group.group1'],
                    tags: { key1: ['tag1', 'tag2'] },
                },
                category: 'group',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.groups['dom:group.group1'].tags = {
            key1: ['tag1', 'tag2'],
        };
        const newState = groups(initialState, action);
        expect(newState).toEqual(expectedState);
    });
    it('should insert to the store a member to group1', () => {
        const initialState = {
            groups: configStoreGroups,
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
    it('should insert to the store a pending member to group1', () => {
        const initialState = {
            groups: configStoreGroupsWithPendingMembers,
            domainName: domainName,
            expiry: expiry,
        };
        let newMember = {
            memberName: 'user.user2',
            expiration: '',
            reviewReminder: '',
            approved: false,
        };
        const action = {
            type: ADD_PENDING_MEMBER_TO_STORE,
            payload: {
                collectionName: 'dom:group.group1',
                category: 'group',
                member: newMember,
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.groups['dom:group.group1'].groupPendingMembers[
            'user.user2'
        ] = newMember;
        const newState = groups(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should delete from the store a member from group1', () => {
        const initialState = {
            groups: configStoreGroups,
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
    it('should delete from the store a pending member', () => {
        const initialState = {
            groups: configStoreGroupsWithPendingMembers,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: DELETE_PENDING_MEMBER_FROM_STORE,
            payload: {
                collectionName: 'dom:group.group1',
                category: 'group',
                memberName: 'user.user4',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        delete expectedState.groups['dom:group.group1'].groupPendingMembers[
            'user.user4'
        ];
        const newState = groups(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should change group settings of group1 in the store', () => {
        const initialState = {
            groups: configStoreGroups,
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
            groups: configStoreGroups,
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
    it('should delete user4 member from the group with review', () => {
        const initialState = {
            groups: configStoreGroups,
            domainName: domainName,
            expiry: expiry,
        };
        let reviewedGroup = {
            groupMembers: {
                'user.user1': {
                    memberName: 'user.user1',
                    groupName: 'dom:group.group1',
                    expiration: '2022-09-02T08:14:08.131Z',
                },
            },
            auditLog: groupAuditLog,
            ç: '2222-02-22T08:14:08.131Z',
            lastReviewedDate: '1111-11-11T14:20:45.836Z',
        };
        const action = {
            type: REVIEW_GROUP,
            payload: {
                groupName: 'dom:group.group1',
                reviewedGroup: reviewedGroup,
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.groups['dom:group.group1'].groupMembers =
            reviewedGroup.groupMembers;
        expectedState.groups['dom:group.group1'].auditLog =
            reviewedGroup.auditLog;
        expectedState.groups['dom:group.group1'].modified =
            reviewedGroup.modified;
        expectedState.groups['dom:group.group1'].lastReviewedDate =
            reviewedGroup.lastReviewedDate;
        const newState = groups(initialState, action);
        expect(newState).toEqual(expectedState);
    });
    it('should approve pending member user.user4 with add state from group', () => {
        let membership = {
            approved: true,
            memberName: 'user.user4',
            groupName: 'dom:group.group1',
            expiration: '2022-09-02T08:14:08.131Z',
            pendingState: PENDING_STATE_ENUM.ADD,
        };
        const initialState = {
            groups: configStoreGroupsWithPendingMembers,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: PROCESS_GROUP_PENDING_MEMBERS_TO_STORE,
            payload: {
                domainName: 'dom',
                groupName: 'group1',
                member: membership,
            },
        };
        let expectedState = AppUtils.deepClone(initialState);
        delete expectedState.groups['dom:group.group1'].groupPendingMembers[
            'user.user4'
        ];
        expectedState.groups['dom:group.group1'].groupMembers['user.user4'] =
            membership;
        const newState = groups(initialState, action);
        expect(newState).toEqual(expectedState);
    });
    it('should deny pending member user.user4 with add state from group', () => {
        let membership = {
            approved: false,
            memberName: 'user.user4',
            groupName: 'dom:group.group1',
            expiration: '2022-09-02T08:14:08.131Z',
            pendingState: PENDING_STATE_ENUM.ADD,
        };
        const initialState = {
            groups: configStoreGroupsWithPendingMembers,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: PROCESS_GROUP_PENDING_MEMBERS_TO_STORE,
            payload: {
                domainName: 'dom',
                groupName: 'group1',
                member: membership,
            },
        };
        let expectedState = AppUtils.deepClone(initialState);
        delete expectedState.groups['dom:group.group1'].groupPendingMembers[
            'user.user4'
        ];
        const newState = groups(initialState, action);
        expect(newState).toEqual(expectedState);
    });
    it('should approve pending member user.user4 with add state from group', () => {
        let membership = {
            approved: true,
            memberName: 'user.user6',
            groupName: 'dom:group.group1',
            expiration: '2022-09-02T08:14:08.131Z',
            pendingState: PENDING_STATE_ENUM.DELETE,
        };
        const initialState = {
            groups: configStoreGroupsWithPendingMembers,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: PROCESS_GROUP_PENDING_MEMBERS_TO_STORE,
            payload: {
                domainName: 'dom',
                groupName: 'group1',
                member: membership,
            },
        };
        let expectedState = AppUtils.deepClone(initialState);
        delete expectedState.groups['dom:group.group1'].groupPendingMembers[
            'user.user6'
        ];
        delete expectedState.groups['dom:group.group1'].groupMembers[
            'user.user6'
        ];
        const newState = groups(initialState, action);
        expect(newState).toEqual(expectedState);
    });
    it('should deny pending member user.user4 with delete state from group', () => {
        let membership = {
            approved: false,
            memberName: 'user.user6',
            groupName: 'dom:group.group1',
            expiration: '2022-09-02T08:14:08.131Z',
            pendingState: PENDING_STATE_ENUM.DELETE,
        };
        const initialState = {
            groups: configStoreGroupsWithPendingMembers,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: PROCESS_GROUP_PENDING_MEMBERS_TO_STORE,
            payload: {
                domainName: 'dom',
                groupName: 'group1',
                member: membership,
            },
        };
        let expectedState = AppUtils.deepClone(initialState);
        delete expectedState.groups['dom:group.group1'].groupPendingMembers[
            'user.user6'
        ];
        const newState = groups(initialState, action);
        expect(newState).toEqual(expectedState);
    });
});
