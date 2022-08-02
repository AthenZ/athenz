import { apiServiceDependenciesData } from '../../config/config.test';
import { selectServiceDependencies } from '../../../redux/selectors/visibility';

describe('test visibility selectors', () => {
    it('should return service dependencies', () => {
        const state = {
            serviceDependencies: {
                serviceDependencies: apiServiceDependenciesData,
            },
        };
        expect(selectServiceDependencies(state)).toEqual(
            apiServiceDependenciesData
        );
    });
    it('should return empty list of service dependencies', () => {
        const state = {
            serviceDependencies: {},
        };
        expect(selectServiceDependencies(state)).toEqual([]);
    });
});
