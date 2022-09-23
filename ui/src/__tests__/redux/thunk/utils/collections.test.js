import { getFullCollectionName } from '../../../../redux/thunks/utils/collection';

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
