import {
    domainName,
    expiry,
    modified,
    storeGroups,
} from '../../config/config.test';
import {
    selectGroup,
    selectGroupHistory,
    selectGroupMembers,
    selectGroupRoleMembers,
    selectGroups,
    selectGroupTags,
    thunkSelectGroups,
} from '../../../redux/selectors/group';

describe('test group selectors', () => {
    const stateWithGroups = {
        groups: {
            domainName,
            expiry,
            groups: storeGroups,
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
            expect(thunkSelectGroups(stateWithGroups)).toEqual(storeGroups);
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
                    expiry: 1658408002704,
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
                expiry: 1658408002704,
            };
            expect(selectGroup(stateWithGroups, domainName, 'group1')).toEqual(
                expectedGroup
            );
        });
        it('should return empty object', () => {
            expect(selectGroup(stateWithoutGroups)).toEqual({});
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
