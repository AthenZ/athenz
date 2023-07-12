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
import {
    ADD_ROLE_TAGS_TO_STORE,
    ADD_ROLE_TO_STORE,
    DELETE_ROLE_FROM_STORE,
    LOAD_ROLE,
    LOAD_ROLES,
    MAKE_ROLES_EXPIRES,
    MARKS_ROLE_AS_NEED_REFRESH,
    RETURN_ROLES,
    REVIEW_ROLE,
} from '../../../redux/actions/roles';
import { roles } from '../../../redux/reducers/roles';
import { _ } from 'lodash';
import { domainName, expiry } from '../../config/config.test';
import { singleStoreRole, configStoreRoles } from '../config/role.test';
import AppUtils from '../../../components/utils/AppUtils';
import {
    ADD_MEMBER_TO_STORE,
    ADD_PENDING_MEMBER_TO_STORE,
    DELETE_MEMBER_FROM_STORE,
    DELETE_PENDING_MEMBER_FROM_STORE,
    UPDATE_SETTING_TO_STORE,
    UPDATE_TAGS_TO_STORE,
} from '../../../redux/actions/collections';
import { PROCESS_ROLE_PENDING_MEMBERS_TO_STORE } from '../../../redux/actions/domains';
import { PENDING_STATE_ENUM } from '../../../components/constants/constants';

const utils = require('../../../redux/utils');

const member = {
    memberName: 'user.user4',
    expiration: '',
    reviewReminder: '',
    approved: true,
};

const roleSetting = {
    reviewEnabled: true,
    selfServe: false,
    memberExpiryDays: '50',
    memberReviewDays: '20',
    groupExpiryDays: '',
    groupReviewDays: '',
    serviceExpiryDays: '30',
    serviceReviewDays: '',
    tokenExpiryMins: '',
    certExpiryMins: '',
    roleCertExpiryMins: '',
    userAuthorityFilter: '',
    userAuthorityExpiration: '',
};

describe('Roles Reducer', () => {
    afterAll(() => {
        jest.spyOn(utils, 'getExpiredTime').mockRestore();
    });
    it('should load the roles into the store', () => {
        const initialState = {};
        const action = {
            type: LOAD_ROLES,
            payload: {
                roles: AppUtils.deepClone(configStoreRoles),
                domainName: domainName,
                expiry: expiry,
            },
        };
        const expectedState = {
            roles: AppUtils.deepClone(configStoreRoles),
            domainName: domainName,
            expiry: expiry,
        };
        const newState = roles(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should load a role into the store', () => {
        const initialState = {
            roles: {},
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: LOAD_ROLE,
            payload: {
                roleData: AppUtils.deepClone(singleStoreRole),
                roleName: 'singlerole',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.roles['singlerole'] = AppUtils.deepClone(singleStoreRole);
        const newState = roles(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should add role to the store', () => {
        const initialState = {
            roles: AppUtils.deepClone(configStoreRoles),
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: ADD_ROLE_TO_STORE,
            payload: {
                roleData: AppUtils.deepClone(singleStoreRole),
                roleName: 'singlerole',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.roles['dom:role.singlerole'] =
            AppUtils.deepClone(singleStoreRole);
        const newState = roles(initialState, action);
        expect(newState).toEqual(expectedState);
    });
    it('should delete role', () => {
        const initialState = {
            roles: AppUtils.deepClone(configStoreRoles),
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: DELETE_ROLE_FROM_STORE,
            payload: {
                roleName: 'dom:role.role1',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        delete expectedState.roles['dom:role.role1'];
        const newState = roles(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should edit tags from expiration', () => {
        const initialState = {
            roles: AppUtils.deepClone(configStoreRoles),
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: UPDATE_TAGS_TO_STORE,
            payload: {
                collectionName: 'dom:role.expiration',
                collectionWithTags: {
                    ...configStoreRoles['dom:role.expiration'],
                    tags: { tag: { list: ['tag4', 'tag5'] } },
                },
                category: 'role',
            },
        };
        let expectedState = AppUtils.deepClone(initialState);
        expectedState.roles['dom:role.expiration'].tags = {
            tag: { list: ['tag4', 'tag5'] },
        };
        const newState = roles(initialState, action);
        expect(newState).toEqual(expectedState);
    });
    it('should add role tag the store', () => {
        const initialState = {
            roles: AppUtils.deepClone(configStoreRoles),
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: UPDATE_TAGS_TO_STORE,
            payload: {
                collectionName: 'dom:role.role1',
                collectionWithTags: {
                    ...configStoreRoles['dom:role.role1'],
                    tags: { tag: { list: ['tag1', 'tag2'] } },
                },
                category: 'role',
            },
        };
        let expectedState = AppUtils.deepClone(initialState);
        expectedState.roles['dom:role.role1'].tags = {
            tag: { list: ['tag1', 'tag2'] },
        };
        const newState = roles(initialState, action);
        expect(newState).toEqual(expectedState);
    });
    it('should delete and edit role tag from store', () => {
        const initialState = {
            roles: AppUtils.deepClone(configStoreRoles),
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: UPDATE_TAGS_TO_STORE,
            payload: {
                collectionName: 'dom:role.expiration',
                collectionWithTags: {
                    ...configStoreRoles['dom:role.expiration'],
                    tags: { tag: { list: ['tag1'] } },
                },
                category: 'role',
            },
        };
        let expectedState = AppUtils.deepClone(initialState);
        expectedState.roles['dom:role.expiration'].tags = {
            tag: { list: ['tag1'] },
        };
        const newState = roles(initialState, action);
        expect(newState).toEqual(expectedState);
    });
    it('should update role setting to store', () => {
        const initialState = {
            roles: AppUtils.deepClone(configStoreRoles),
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: UPDATE_SETTING_TO_STORE,
            payload: {
                collectionName: 'dom:role.expiration',
                collectionSettings: roleSetting,
                category: 'role',
            },
        };
        let expectedState = AppUtils.deepClone(initialState);
        expectedState.roles['dom:role.expiration'] = {
            ...expectedState.roles['dom:role.expiration'],
            ...roleSetting,
        };
        const newState = roles(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should add member to role1 in the store', () => {
        const initialState = {
            roles: AppUtils.deepClone(configStoreRoles),
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: ADD_MEMBER_TO_STORE,
            payload: {
                member: member,
                category: 'role',
                collectionName: 'dom:role.role1',
            },
        };
        let expectedState = AppUtils.deepClone(initialState);
        expectedState.roles['dom:role.role1'].roleMembers['user.user4'] =
            member;
        const newState = roles(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should add a pending member to role1 in the store', () => {
        const initialState = {
            roles: AppUtils.deepClone(configStoreRoles),
            domainName: domainName,
            expiry: expiry,
        };
        const newMember = {
            memberName: 'user.user4',
            expiration: '',
            reviewReminder: '',
            approved: false,
            pendingState: PENDING_STATE_ENUM.ADD,
        };
        const action = {
            type: ADD_PENDING_MEMBER_TO_STORE,
            payload: {
                member: newMember,
                category: 'role',
                collectionName: 'dom:role.role1',
            },
        };
        let expectedState = AppUtils.deepClone(initialState);
        expectedState.roles['dom:role.role1'].rolePendingMembers['user.user4'] =
            newMember;
        const newState = roles(initialState, action);
        expect(newState).toEqual(expectedState);
    });
    it('should delete member from role1 from the store', () => {
        const initialState = {
            roles: AppUtils.deepClone(configStoreRoles),
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: DELETE_MEMBER_FROM_STORE,
            payload: {
                memberName: 'user.user1',
                category: 'role',
                collectionName: 'dom:role.role1',
            },
        };
        let expectedState = AppUtils.deepClone(initialState);
        delete expectedState.roles['dom:role.role1'].roleMembers['user.user1'];
        const newState = roles(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should delete a pending member from role1 from the store', () => {
        const initialState = {
            roles: AppUtils.deepClone(configStoreRoles),
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: DELETE_PENDING_MEMBER_FROM_STORE,
            payload: {
                memberName: 'user.user3',
                category: 'role',
                collectionName: 'dom:role.role1',
            },
        };
        let expectedState = AppUtils.deepClone(initialState);
        delete expectedState.roles['dom:role.role1'].rolePendingMembers[
            'user.user3'
        ];
        const newState = roles(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should delete by review role1 from the store', () => {
        const initialState = {
            roles: AppUtils.deepClone(configStoreRoles),
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: REVIEW_ROLE,
            payload: {
                roleName: 'dom:role.role1',
                reviewedRole: {
                    roleMembers: {
                        'user.user2': {
                            memberName: 'user.user2',
                            expiration: expiry,
                            principalType: 1,
                            memberFullName: 'user.user2',
                        },
                    },
                    rolePendingMembers: {
                        'user.user3': {
                            active: false,
                            approved: false,
                            auditRef: 'added using Athenz UI',
                            expiration: expiry,
                            memberFullName: 'user.user3',
                            requestedTime: expiry,
                        },
                    },
                    lastReviewedDate: '2022-07-18T13:42:54.907Z',
                    modified: '2022-10-02T14:37:49.573Z',
                },
            },
        };
        let expectedState = AppUtils.deepClone(initialState);
        delete expectedState.roles['dom:role.role1'].roleMembers['user.user1'];
        const newState = roles(initialState, action);
        expect(newState).toEqual(expectedState);
    });
    it('should approve pending member user.user4 from expiration role', () => {
        let memberShip = {
            approved: true,
            expiration: '2022-09-27T10:10:33.431Z',
            memberName: 'user.user4',
            reviewReminder: undefined,
            pendingState: PENDING_STATE_ENUM.ADD,
        };
        const initialState = {
            roles: AppUtils.deepClone(configStoreRoles),
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: PROCESS_ROLE_PENDING_MEMBERS_TO_STORE,
            payload: {
                domainName: 'dom',
                roleName: 'expiration',
                member: memberShip,
            },
        };
        let expectedState = AppUtils.deepClone(initialState);
        delete expectedState.roles['dom:role.expiration'].rolePendingMembers[
            'user.user4'
        ];
        expectedState.roles['dom:role.expiration'].roleMembers['user.user4'] =
            memberShip;
        const newState = roles(initialState, action);
        expect(newState).toEqual(expectedState);
    });
    it('should approve pending member user.user6 with delete state from expiration role', () => {
        let membership = {
            memberName: 'user.user6',
            expiration: null,
            principalType: 1,
            memberFullName: null,
            pendingState: PENDING_STATE_ENUM.DELETE,
            approved: true,
            reviewReminder: undefined,
        };
        const initialState = {
            roles: AppUtils.deepClone(configStoreRoles),
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: PROCESS_ROLE_PENDING_MEMBERS_TO_STORE,
            payload: {
                domainName: 'dom',
                roleName: 'expiration',
                member: membership,
            },
        };
        let expectedState = AppUtils.deepClone(initialState);
        delete expectedState.roles['dom:role.expiration'].rolePendingMembers[
            'user.user6'
        ];
        delete expectedState.roles['dom:role.expiration'].roleMembers[
            'user.user6'
        ];
        const newState = roles(initialState, action);
        expect(newState).toEqual(expectedState);
    });
    it('should deny pending member user.user4 from expiration role', () => {
        let memberShip = {
            approved: false,
            expiration: '2022-09-27T10:10:33.431Z',
            memberName: 'user.user4',
            reviewReminder: undefined,
            pendingState: PENDING_STATE_ENUM.ADD,
        };
        const initialState = {
            roles: AppUtils.deepClone(configStoreRoles),
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: PROCESS_ROLE_PENDING_MEMBERS_TO_STORE,
            payload: {
                domainName: 'dom',
                roleName: 'expiration',
                member: memberShip,
            },
        };
        let expectedState = AppUtils.deepClone(initialState);
        delete expectedState.roles['dom:role.expiration'].rolePendingMembers[
            'user.user4'
        ];
        const newState = roles(initialState, action);
        expect(newState).toEqual(expectedState);
    });
    it('should deny pending member user.user6 with delete state from expiration role', () => {
        let membership = {
            memberName: 'user.user6',
            expiration: null,
            principalType: 1,
            memberFullName: null,
            pendingState: PENDING_STATE_ENUM.DELETE,
            approved: false,
            reviewReminder: undefined,
        };
        const initialState = {
            roles: AppUtils.deepClone(configStoreRoles),
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: PROCESS_ROLE_PENDING_MEMBERS_TO_STORE,
            payload: {
                domainName: 'dom',
                roleName: 'expiration',
                member: membership,
            },
        };
        let expectedState = AppUtils.deepClone(initialState);
        delete expectedState.roles['dom:role.expiration'].rolePendingMembers[
            'user.user6'
        ];
        const newState = roles(initialState, action);
        expect(newState).toEqual(expectedState);
    });
    it('should marks role as need refresh', () => {
        const initialState = {
            roles: AppUtils.deepClone(configStoreRoles),
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: MARKS_ROLE_AS_NEED_REFRESH,
            payload: {
                domainName: 'dom',
                roleName: 'role1',
                needRefresh: true,
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.roles['dom:role.role1']['needRefresh'] = true;
        const newState = roles(initialState, action);
        expect(newState).toEqual(expectedState);
    });
    it('should make roles expires', () => {
        jest.spyOn(utils, 'getExpiredTime').mockReturnValue(-1);
        const initialState = {
            roles: AppUtils.deepClone(configStoreRoles),
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: MAKE_ROLES_EXPIRES,
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.expiry = -1;
        const newState = roles(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should return same state', () => {
        const initialState = {
            roles: AppUtils.deepClone(configStoreRoles),
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: RETURN_ROLES,
        };
        const expectedState = AppUtils.deepClone(initialState);
        const newState = roles(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
});
