import { selectIsLoading } from '../../../redux/selectors/loading';

describe('test loading selectors', () => {
    it('should select loading from state', () => {
        const state = {
            roles: {},
            groups: {},
            policies: {},
            loading: ['getPolicies', 'getRoles'],
        };
        expect(selectIsLoading(state)).toEqual(['getPolicies', 'getRoles']);
    });
});
