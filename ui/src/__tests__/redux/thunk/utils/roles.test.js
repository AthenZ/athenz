import { mergeUserListWithRoleListData } from '../../../../redux/thunks/utils/roles';

const rolesSelectors = require('../../../../redux/selectors/roles');
const {
    checkIfMemberInAllRoles,
} = require('../../../../redux/thunks/utils/roles');

describe('test roles thunk utils', () => {
    it('test mergeUserListWithRoleListData func', () => {
        const roleMap = {
            'dom:role.role1': {
                name: 'dom:role.role1',
                roleMembers: {
                    'user.user1': {
                        memberName: 'user.user1',
                    },
                },
            },
            'dom:role.role2': {
                name: 'dom:role.role2',
                roleMembers: {
                    'user.user2': {
                        memberName: 'user.user2',
                    },
                },
            },
        };
        const userMap = {
            'user.user1': {
                memberFullName: 'user.user1',
            },
            'user.user2': {
                memberFullName: null,
            },
        };
        const exceptedMergedMap = {
            'dom:role.role1': {
                name: 'dom:role.role1',
                roleMembers: {
                    'user.user1': {
                        memberName: 'user.user1',
                        memberFullName: 'user.user1',
                    },
                },
            },
            'dom:role.role2': {
                name: 'dom:role.role2',
                roleMembers: {
                    'user.user2': {
                        memberName: 'user.user2',
                        memberFullName: null,
                    },
                },
            },
        };
        expect(mergeUserListWithRoleListData(roleMap, userMap)).toEqual(
            exceptedMergedMap
        );
    });
    describe('test checkIfMemberInAllRoles func', () => {
        afterEach(() => {
            jest.spyOn(rolesSelectors, 'thunkSelectRoleMembers').mockRestore();
        });
        it('should return true', () => {
            const roleList = ['role1', 'role2'];
            jest.spyOn(
                rolesSelectors,
                'thunkSelectRoleMembers'
            ).mockReturnValue({
                'user.user1': {
                    memberName: 'user.user1',
                },
                'user.user2': {
                    memberName: 'user.user2',
                },
            });
            expect(
                checkIfMemberInAllRoles('dom', {}, roleList, 'user.user1')
            ).toBe(true);
        });
        it('should return false', () => {
            const roleList = ['role1', 'role2'];
            jest.spyOn(rolesSelectors, 'thunkSelectRoleMembers')
                .mockReturnValueOnce({
                    'user.user1': {
                        memberName: 'user.user1',
                    },
                    'user.user2': {
                        memberName: 'user.user2',
                    },
                })
                .mockReturnValue({
                    'user.user2': {
                        memberName: 'user.user2',
                    },
                });
            expect(
                checkIfMemberInAllRoles('dom', {}, roleList, 'user.user1')
            ).toBe(false);
        });
    });
});
