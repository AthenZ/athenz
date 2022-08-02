import {
    domainName,
    expiry,
    modified,
    storeRoles,
} from '../../config/config.test';
import {
    selectRole,
    selectRoleHistory,
    selectRoleMembers,
    selectRoles,
    selectRoleTags,
    selectRoleUsers,
    thunkSelectRoleMembers,
    thunkSelectRoles,
} from '../../../redux/selectors/roles';

describe('test role selectors', () => {
    const stateWithRoles = {
        roles: {
            domainName,
            expiry,
            roles: storeRoles,
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
            expect(thunkSelectRoles(stateWithRoles)).toEqual(storeRoles);
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
                            expiration: '2022-10-02T14:37:10.600Z',
                            principalType: 1,
                            memberFullName: 'user.user2',
                        },
                    },
                    lastReviewedDate: '2022-07-18T13:42:54.907Z',
                },
                {
                    modified: modified,
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
                    roleMembers: {
                        'user.user2': {
                            memberName: 'user.user2',
                            expiration: '2022-08-19T14:17:35.267Z',
                            principalType: 1,
                            memberFullName: null,
                        },
                        'user.user3': {
                            memberName: 'user.user7',
                            expiration: '2022-10-02T14:37:10.600Z',
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
                },
                {
                    memberExpiryDays: 100,
                    reviewEnabled: true,
                    tags: { tag: { list: ['tag1', 'tag2'] } },
                    name: 'dom:role.expiration',
                    modified: modified,
                    roleMembers: {
                        'user.user4': {
                            memberName: 'user.user4',
                            expiration: '2022-10-22T07:48:59.105Z',
                            principalType: 1,
                            memberFullName: null,
                        },
                        'user.user6': {
                            memberName: 'user.user6',
                            expiration: '2022-10-22T07:50:04.579Z',
                            principalType: 1,
                            memberFullName: null,
                        },
                        'user.user2': {
                            memberName: 'user.user6',
                            expiration: '2022-10-22T07:48:59.105Z',
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
                        expiration: '2022-08-19T14:17:35.267Z',
                        principalType: 1,
                        memberFullName: null,
                    },
                    'user.user3': {
                        memberName: 'user.user7',
                        expiration: '2022-10-02T14:37:10.600Z',
                        principalType: 1,
                        memberFullName: null,
                    },
                },
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
                    expiration: '2022-08-19T14:17:35.267Z',
                    principalType: 1,
                    memberFullName: null,
                },
                'user.user3': {
                    memberName: 'user.user7',
                    expiration: '2022-10-02T14:37:10.600Z',
                    principalType: 1,
                    memberFullName: null,
                },
            };
            expect(
                thunkSelectRoleMembers(stateWithRoles, domainName, 'admin')
            ).toEqual(expectedRoleMembers);
        });
        it('should return empty list', () => {
            expect(
                thunkSelectRoleMembers(stateWithoutRoles, domainName, 'admin')
            ).toEqual([]);
        });
    });
    describe('test selectRoleMembers selector', () => {
        it('should return role members list', () => {
            const expectedRoleMembersList = [
                {
                    memberName: 'user.user2',
                    expiration: '2022-08-19T14:17:35.267Z',
                    principalType: 1,
                    memberFullName: null,
                },
                {
                    memberName: 'user.user7',
                    expiration: '2022-10-02T14:37:10.600Z',
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
                    expiration: '2022-07-18T14:37:49.671Z',
                    principalType: 1,
                    memberFullName: 'user.user1',
                    memberRoles: [
                        {
                            roleName: 'dom:role.role1',
                            expiration: '2022-07-18T14:37:49.671Z',
                        },
                    ],
                },
                {
                    memberName: 'user.user2',
                    expiration: '2022-10-02T14:37:10.600Z',
                    principalType: 1,
                    memberFullName: 'user.user2',
                    memberRoles: [
                        {
                            roleName: 'dom:role.role1',
                            expiration: '2022-10-02T14:37:10.600Z',
                        },
                        {
                            roleName: 'dom:role.admin',
                            expiration: '2022-08-19T14:17:35.267Z',
                        },
                        {
                            roleName: 'dom:role.expiration',
                            expiration: '2022-10-22T07:48:59.105Z',
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
                    expiration: '2022-10-02T14:37:10.600Z',
                    principalType: 1,
                    memberFullName: null,
                    memberRoles: [
                        {
                            roleName: 'dom:role.admin',
                            expiration: '2022-10-02T14:37:10.600Z',
                        },
                    ],
                },
                {
                    memberName: 'user.user4',
                    expiration: '2022-10-22T07:48:59.105Z',
                    principalType: 1,
                    memberFullName: null,
                    memberRoles: [
                        {
                            roleName: 'dom:role.expiration',
                            expiration: '2022-10-22T07:48:59.105Z',
                        },
                    ],
                },
                {
                    memberName: 'user.user6',
                    expiration: '2022-10-22T07:50:04.579Z',
                    principalType: 1,
                    memberFullName: null,
                    memberRoles: [
                        {
                            roleName: 'dom:role.expiration',
                            expiration: '2022-10-22T07:50:04.579Z',
                        },
                    ],
                },
            ];
            const c = selectRoleUsers(stateWithRoles);
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
