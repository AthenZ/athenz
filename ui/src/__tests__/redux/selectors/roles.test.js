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
import { domainName, expiry, modified } from '../../config/config.test';
import { configStoreRoles } from '../config/role.test';
import {
    selectReviewRoleMembers,
    selectRole,
    selectRoleHistory,
    selectRoleMembers,
    selectRoles,
    selectRoleTags,
    selectRoleUsers,
    thunkSelectRoleMember,
    thunkSelectRoleMembers,
    thunkSelectRoles,
} from '../../../redux/selectors/roles';
import { PENDING_STATE_ENUM } from '../../../components/constants/constants';

describe('test role selectors', () => {
    const stateWithRoles = {
        roles: {
            domainName,
            expiry,
            roles: configStoreRoles,
        },
    };
    const stateWithoutRoles = {
        roles: {
            domainName,
            expiry,
        },
    };
    describe('test thunkSelectRoles selector', () => {
        it('should return roles', () => {
            expect(thunkSelectRoles(stateWithRoles)).toEqual(configStoreRoles);
        });
        it('should return empty object', () => {
            expect(thunkSelectRoles(stateWithoutRoles)).toEqual({});
        });
    });
    describe('test selectRoles selector', () => {
        it('should return role list', () => {
            const expectedRolesList = [
                {
                    name: 'dom:role.role1',
                    modified: modified,
                    roleMembers: {
                        'user.user1': {
                            memberName: 'user.user1',
                            expiration: expiry,
                            principalType: 1,
                            memberFullName: 'user.user1',
                        },
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
                            pendingState: PENDING_STATE_ENUM.ADD,
                        },
                    },
                    lastReviewedDate: '2022-07-18T13:42:54.907Z',
                },
                {
                    modified: modified,
                    rolePendingMembers: {},
                    roleMembers: {
                        'yamas.api': {
                            memberName: 'yamas.api',
                            principalType: 1,
                            memberFullName: null,
                        },
                    },
                },
                {
                    modified: modified,
                    rolePendingMembers: {},
                    roleMembers: {
                        'sys.auth': {
                            memberName: 'sys.auth',
                            principalType: 1,
                            memberFullName: null,
                        },
                    },
                },
                {
                    tags: { tag: { list: ['tag1'] } },
                    name: 'dom:role.admin',
                    modified: modified,
                    rolePendingMembers: {},
                    roleMembers: {
                        'user.user2': {
                            memberName: 'user.user2',
                            expiration: expiry,
                            principalType: 1,
                            memberFullName: null,
                        },
                        'user.user3': {
                            memberName: 'user.user7',
                            expiration: expiry,
                            principalType: 1,
                            memberFullName: null,
                        },
                    },
                },
                {
                    name: 'dom:role.empty',
                    modified: modified,
                    auditLog: 'for test',
                    roleMembers: {},
                    rolePendingMembers: {},
                },
                {
                    memberExpiryDays: 100,
                    reviewEnabled: true,
                    tags: { tag: { list: ['tag1', 'tag2'] } },
                    name: 'dom:role.expiration',
                    modified: modified,
                    rolePendingMembers: {
                        'user.user4': {
                            memberName: 'user.user4',
                            expiration: expiry,
                            approved: false,
                            principalType: 1,
                            memberFullName: null,
                            pendingState: PENDING_STATE_ENUM.ADD,
                        },
                        'user.user6': {
                            memberName: 'user.user6',
                            expiration: null,
                            approved: false,
                            principalType: 1,
                            memberFullName: null,
                            pendingState: PENDING_STATE_ENUM.DELETE,
                        },
                    },
                    roleMembers: {
                        'user.user6': {
                            memberName: 'user.user6',
                            expiration: expiry,
                            principalType: 1,
                            memberFullName: null,
                        },
                        'user.user2': {
                            memberName: 'user.user2',
                            expiration: expiry,
                            principalType: 1,
                            memberFullName: null,
                        },
                    },
                },
            ];
            expect(selectRoles(stateWithRoles)).toEqual(expectedRolesList);
        });
        it('should return empty list', () => {
            expect(selectRoles(stateWithoutRoles)).toEqual([]);
        });
    });
    describe('test selectRole selector', () => {
        it('should return role', () => {
            const expectedRole = {
                tags: { tag: { list: ['tag1'] } },
                name: 'dom:role.admin',
                modified: modified,
                roleMembers: {
                    'user.user2': {
                        memberName: 'user.user2',
                        expiration: expiry,
                        principalType: 1,
                        memberFullName: null,
                    },
                    'user.user3': {
                        memberName: 'user.user7',
                        expiration: expiry,
                        principalType: 1,
                        memberFullName: null,
                    },
                },
                rolePendingMembers: {},
            };
            expect(selectRole(stateWithRoles, domainName, 'admin')).toEqual(
                expectedRole
            );
        });
        it('should return empty object', () => {
            expect(selectRole(stateWithoutRoles, domainName, 'admin')).toEqual(
                {}
            );
        });
    });
    describe('test thunkSelectRoleMembers selector', () => {
        it('should return role members list', () => {
            const expectedRoleMembers = {
                'user.user2': {
                    memberName: 'user.user2',
                    expiration: expiry,
                    principalType: 1,
                    memberFullName: null,
                },
                'user.user3': {
                    memberName: 'user.user7',
                    expiration: expiry,
                    principalType: 1,
                    memberFullName: null,
                },
            };
            expect(
                thunkSelectRoleMembers(stateWithRoles, domainName, 'admin')
            ).toEqual(expectedRoleMembers);
        });
        it('should return empty object', () => {
            expect(
                thunkSelectRoleMembers(stateWithoutRoles, domainName, 'admin')
            ).toEqual({});
        });
    });
    describe('test selectRoleMembers selector', () => {
        it('should return role members list', () => {
            const expectedRoleMembersList = [
                {
                    memberName: 'user.user2',
                    expiration: expiry,
                    principalType: 1,
                    memberFullName: null,
                },
                {
                    memberName: 'user.user7',
                    expiration: expiry,
                    principalType: 1,
                    memberFullName: null,
                },
            ];
            expect(
                selectRoleMembers(stateWithRoles, domainName, 'admin')
            ).toEqual(expectedRoleMembersList);
        });
        it('should return empty list', () => {
            expect(
                selectRoleMembers(stateWithoutRoles, domainName, 'admin')
            ).toEqual([]);
        });
    });
    describe('test thunkSelectRoleMember selector', () => {
        const expectedRoleMember = {
            memberName: 'user.user2',
            expiration: expiry,
            principalType: 1,
            memberFullName: null,
        };
        it('should return user2 ', () => {
            expect(
                thunkSelectRoleMember(
                    stateWithRoles,
                    domainName,
                    'admin',
                    'user.user2'
                )
            ).toEqual(expectedRoleMember);
        });
        it('should return empty object', () => {
            expect(
                thunkSelectRoleMember(
                    stateWithRoles,
                    domainName,
                    'admin',
                    'user.unknown'
                )
            ).toEqual({});
        });
    });
    describe('test selectReviewRoleMembers selector', () => {
        it('should return role members list', () => {
            const roles = {
                'dom:role.role1': {
                    name: 'dom:role.role1',
                    modified: modified,
                    roleMembers: {
                        'user.user1': {
                            memberName: 'user.user1',
                            expiration: expiry,
                            principalType: 1,
                            approved: true,
                            memberFullName: 'user.user1',
                        },
                        'user.user2': {
                            memberName: 'user.user2',
                            expiration: expiry,
                            principalType: 1,
                            approved: false,
                            memberFullName: 'user.user2',
                        },
                        'user.user3': {
                            active: false,
                            approved: true,
                            auditRef: 'added using Athenz UI',
                            expiration: expiry,
                            memberFullName: 'user.user3',
                            requestedTime: expiry,
                        },
                    },
                    lastReviewedDate: '2022-07-18T13:42:54.907Z',
                },
            };
            const state = {
                roles: {
                    domainName,
                    expiry,
                    roles,
                },
            };
            const expectedReviewRoleMembersList = [
                {
                    memberName: 'user.user1',
                    expiration: expiry,
                    principalType: 1,
                    approved: true,
                    memberFullName: 'user.user1',
                },
                {
                    active: false,
                    approved: true,
                    auditRef: 'added using Athenz UI',
                    expiration: expiry,
                    memberFullName: 'user.user3',
                    requestedTime: expiry,
                },
            ];
            expect(selectReviewRoleMembers(state, 'dom', 'role1')).toEqual(
                expectedReviewRoleMembersList
            );
        });
        it('should return empty list', () => {
            expect(
                selectReviewRoleMembers(stateWithoutRoles, 'dom', 'role1')
            ).toEqual([]);
        });
    });
    describe('test selectRoleTags selector', () => {
        it('should return role tags', () => {
            const expectedRoleTags = { tag: { list: ['tag1'] } };
            expect(selectRoleTags(stateWithRoles, domainName, 'admin')).toEqual(
                expectedRoleTags
            );
        });
        it('should return empty object', () => {
            expect(
                selectRoleTags(stateWithoutRoles, domainName, 'admin')
            ).toEqual({});
        });
    });
    describe('test selectRoleUsers selector', () => {
        it('should return role users', () => {
            const expectedRoleUsers = [
                {
                    memberName: 'user.user1',
                    expiration: expiry,
                    principalType: 1,
                    memberFullName: 'user.user1',
                    memberRoles: [
                        {
                            roleName: 'dom:role.role1',
                            expiration: expiry,
                        },
                    ],
                },
                {
                    memberName: 'user.user2',
                    expiration: expiry,
                    principalType: 1,
                    memberFullName: 'user.user2',
                    memberRoles: [
                        {
                            roleName: 'dom:role.role1',
                            expiration: expiry,
                        },
                        {
                            roleName: 'dom:role.admin',
                            expiration: expiry,
                        },
                        {
                            roleName: 'dom:role.expiration',
                            expiration: expiry,
                        },
                    ],
                },
                {
                    memberName: 'yamas.api',
                    principalType: 1,
                    memberFullName: null,
                    memberRoles: [
                        {
                            roleName: 'dom:role.acl.ows.inbound-test1',
                        },
                    ],
                },
                {
                    memberName: 'sys.auth',
                    principalType: 1,
                    memberFullName: null,
                    memberRoles: [
                        {
                            roleName: 'dom:role.acl.ows.outbound-test2',
                        },
                    ],
                },
                {
                    memberName: 'user.user7',
                    expiration: expiry,
                    principalType: 1,
                    memberFullName: null,
                    memberRoles: [
                        {
                            roleName: 'dom:role.admin',
                            expiration: expiry,
                        },
                    ],
                },
                {
                    memberName: 'user.user6',
                    expiration: expiry,
                    principalType: 1,
                    memberFullName: null,
                    memberRoles: [
                        {
                            roleName: 'dom:role.expiration',
                            expiration: expiry,
                        },
                    ],
                },
            ];
            expect(selectRoleUsers(stateWithRoles)).toEqual(expectedRoleUsers);
        });
        it('should return empty list', () => {
            expect(selectRoleUsers(stateWithoutRoles)).toEqual([]);
        });
    });
    describe('test selectRoleHistory selector', () => {
        it('should return role history', () => {
            const expectedRoleHistory = 'for test';
            expect(
                selectRoleHistory(stateWithRoles, domainName, 'empty')
            ).toEqual(expectedRoleHistory);
        });
        it('should return empty list', () => {
            expect(
                selectRoleHistory(stateWithoutRoles, domainName, 'empty')
            ).toEqual([]);
        });
    });
});
