import {
    buildMembersMapName,
    getFullCollectionName,
} from '../../../../redux/thunks/utils/collection';

describe('test getFullCollectionName func', () => {
    it('should return full group name', () => {
        expect(getFullCollectionName('dom', 'test', 'group')).toEqual(
            'dom:group.test'
        );
    });
    it('should return full role name', () => {
        expect(getFullCollectionName('dom', 'test', 'role')).toEqual(
            'dom:role.test'
        );
    });
    it('should return domain name', () => {
        expect(getFullCollectionName('dom', 'dom', 'domain')).toEqual('dom');
    });
});

describe('test buildMembersMapName func', () => {
    it('should return group members map name', () => {
        expect(buildMembersMapName('group', false)).toEqual('groupMembers');
    });
    it('should return group pending members map name', () => {
        expect(buildMembersMapName('group', true)).toEqual(
            'groupPendingMembers'
        );
    });
    it('should return role members map name', () => {
        expect(buildMembersMapName('role', false)).toEqual('roleMembers');
    });
    it('should return role pending members map name', () => {
        expect(buildMembersMapName('role', true)).toEqual('rolePendingMembers');
    });
});
