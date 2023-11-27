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
import { configStoreGroups } from '../config/group.test';
import {
    selectGroup,
    selectGroupHistory,
    selectGroupMembers,
    selectGroups,
    selectGroupTags,
    selectReviewGroupMembers,
    thunkSelectGroupMember,
    thunkSelectGroupMembers,
    thunkSelectGroups,
} from '../../../redux/selectors/groups';

describe('test group selectors', () => {
    const stateWithGroups = {
        groups: {
            domainName,
            expiry,
            groups: configStoreGroups,
        },
    };
    const stateWithoutGroups = {
        groups: {
            domainName,
            expiry,
        },
    };
    describe('test thunkSelectGroups selector', () => {
        it('should return groups', () => {
            expect(thunkSelectGroups(stateWithGroups)).toEqual(
                configStoreGroups
            );
        });
        it('should return empty object', () => {
            expect(thunkSelectGroups(stateWithoutGroups)).toEqual({});
        });
    });
    describe('test selectGroups selector', () => {
        it('should return groups', () => {
            const expectedGroupList = [
                {
                    name: 'dom:group.group1',
                    modified: modified,
                    auditLog: 'for test',
                    groupMembers: {
                        'user.user4': {
                            memberName: 'user.user4',
                            groupName: 'dom:group.group1',
                            expiration: '2022-09-02T08:14:08.131Z',
                        },
                        'user.user1': {
                            memberName: 'user.user1',
                            groupName: 'dom:group.group1',
                            expiration: '2022-09-02T08:14:08.131Z',
                        },
                    },
                    groupPendingMembers: {},
                },
                {
                    memberExpiryDays: 50,
                    tags: {
                        tag: { list: ['tag1', 'tag2'] },
                        tag2: { list: ['tag3'] },
                    },
                    name: 'dom:group.expiration',
                    modified: modified,
                    groupMembers: {
                        'user.user4': {
                            memberName: 'user.user4',
                            groupName: 'dom:group.expiration',
                            expiration: '2022-08-25T15:39:23.701Z',
                        },
                        'user.user1': {
                            memberName: 'user.user1',
                            groupName: 'dom:group.expiration',
                            expiration: '2022-08-25T15:39:23.701Z',
                        },
                    },
                    groupPendingMembers: {},
                    lastReviewedDate: '2022-07-18T14:20:45.836Z',
                    expiry: 1658408002704,
                },
            ];
            expect(selectGroups(stateWithGroups)).toEqual(expectedGroupList);
        });
        it('should return empty list', () => {
            expect(selectGroups(stateWithoutGroups)).toEqual([]);
        });
    });
    describe('test selectGroup selector', () => {
        it('should return group', () => {
            const expectedGroup = {
                name: 'dom:group.group1',
                modified: modified,
                auditLog: 'for test',
                groupMembers: {
                    'user.user4': {
                        memberName: 'user.user4',
                        groupName: 'dom:group.group1',
                        expiration: '2022-09-02T08:14:08.131Z',
                    },
                    'user.user1': {
                        memberName: 'user.user1',
                        groupName: 'dom:group.group1',
                        expiration: '2022-09-02T08:14:08.131Z',
                    },
                },
                groupPendingMembers: {},
            };
            expect(selectGroup(stateWithGroups, domainName, 'group1')).toEqual(
                expectedGroup
            );
        });
        it('should return empty object', () => {
            expect(selectGroup(stateWithoutGroups)).toEqual({});
        });
    });
    describe('test thunkSelectGroupMembers selector', () => {
        it('should return group members', () => {
            const expectedGroupMembers = {
                'user.user4': {
                    memberName: 'user.user4',
                    groupName: 'dom:group.group1',
                    expiration: '2022-09-02T08:14:08.131Z',
                },
                'user.user1': {
                    memberName: 'user.user1',
                    groupName: 'dom:group.group1',
                    expiration: '2022-09-02T08:14:08.131Z',
                },
            };
            expect(
                thunkSelectGroupMembers(stateWithGroups, domainName, 'group1')
            ).toEqual(expectedGroupMembers);
        });
        it('should return empty object', () => {
            expect(
                thunkSelectGroupMembers(stateWithoutGroups, domainName, 'admin')
            ).toEqual({});
        });
    });
    describe('test selectGroupMembers selector', () => {
        it('should return group members', () => {
            const expectedGroupMembersList = [
                {
                    memberName: 'user.user4',
                    groupName: 'dom:group.group1',
                    expiration: '2022-09-02T08:14:08.131Z',
                },
                {
                    memberName: 'user.user1',
                    groupName: 'dom:group.group1',
                    expiration: '2022-09-02T08:14:08.131Z',
                },
            ];
            expect(
                selectGroupMembers(stateWithGroups, domainName, 'group1')
            ).toEqual(expectedGroupMembersList);
        });
        it('should return empty list', () => {
            expect(selectGroupMembers(stateWithoutGroups)).toEqual([]);
        });
    });
    describe('test selectReviewGroupMembers selector', () => {
        it('should return group members', () => {
            const state = {
                groups: {
                    domainName,
                    expiry,
                    groups: {
                        'dom:group.group1': {
                            name: 'dom:group.group1',
                            modified: modified,
                            auditLog: 'for test',
                            groupMembers: {
                                'user.user4': {
                                    memberName: 'user.user4',
                                    groupName: 'dom:group.group1',
                                    expiration: '2022-09-02T08:14:08.131Z',
                                    approved: false,
                                },
                                'user.user1': {
                                    memberName: 'user.user1',
                                    groupName: 'dom:group.group1',
                                    expiration: '2022-09-02T08:14:08.131Z',
                                    approved: true,
                                },
                            },
                        },
                    },
                },
            };
            const expectedGroupMembersList = [
                {
                    memberName: 'user.user1',
                    groupName: 'dom:group.group1',
                    expiration: '2022-09-02T08:14:08.131Z',
                    approved: true,
                },
            ];
            expect(
                selectReviewGroupMembers(state, domainName, 'group1')
            ).toEqual(expectedGroupMembersList);
        });
        it('should return empty list', () => {
            expect(
                selectReviewGroupMembers(
                    stateWithoutGroups,
                    domainName,
                    'group1'
                )
            ).toEqual([]);
        });
    });
    describe('test thunkSelectGroupMember selector', () => {
        it('should return group member', () => {
            const expectedGroupMember = {
                memberName: 'user.user4',
                groupName: 'dom:group.group1',
                expiration: '2022-09-02T08:14:08.131Z',
            };
            expect(
                thunkSelectGroupMember(
                    stateWithGroups,
                    domainName,
                    'group1',
                    'user.user4'
                )
            ).toEqual(expectedGroupMember);
        });
        it('should return empty object', () => {
            expect(
                thunkSelectGroupMember(
                    stateWithGroups,
                    domainName,
                    'group1',
                    'user.notfound'
                )
            ).toEqual({});
        });
    });
    describe('test selectGroupHistory selector', () => {
        it('should return group history', () => {
            const expectedAuditLog = 'for test';
            expect(
                selectGroupHistory(stateWithGroups, domainName, 'group1')
            ).toEqual(expectedAuditLog);
        });
        it('should return empty list', () => {
            expect(selectGroupHistory(stateWithoutGroups)).toEqual([]);
        });
    });
    // describe('test selectGroupRoleMembers selector', () => {
    //     it('should return group role members', () => {
    //         const expectedAuditLog = 'for test';
    //         expect(
    //             selectGroupRoleMembers(stateWithGroups, domainName, 'group1')
    //         ).toEqual(expectedAuditLog);
    //     });
    //     it('should return empty object', () => {
    //         expect(selectGroupRoleMembers(stateWithoutGroups)).toEqual([]);
    //     });
    // });
    describe('test selectGroupTags selector', () => {
        it('should return group tags', () => {
            const expectedGroupTags = {
                tag: { list: ['tag1', 'tag2'] },
                tag2: { list: ['tag3'] },
            };
            expect(
                selectGroupTags(stateWithGroups, domainName, 'expiration')
            ).toEqual(expectedGroupTags);
        });
        it('should return empty object', () => {
            expect(selectGroupTags(stateWithoutGroups)).toEqual({});
        });
    });
});
