import {
    apiServiceDependenciesData,
    domainName,
    expiry,
} from '../../config/config.test';
import { _ } from 'lodash';
import { LOAD_SERVICE_DEPENDENCIES } from '../../../redux/actions/visibility';
import { serviceDependencies } from '../../../redux/reducers/visibility';
import { RETURN_ROLES } from '../../../redux/actions/roles';
import AppUtils from '../../../components/utils/AppUtils';
import { roles } from '../../../redux/reducers/roles';

describe('Visibility Reducer', () => {
    it('should load the serviceDependencies in', () => {
        const initialState = {};
        const action = {
            type: LOAD_SERVICE_DEPENDENCIES,
            payload: {
                serviceDependencies: apiServiceDependenciesData,
                domainName: domainName,
                expiry: expiry,
            },
        };
        const expectedState = {
            serviceDependencies: apiServiceDependenciesData,
            domainName: domainName,
            expiry: expiry,
        };
        const newState = serviceDependencies(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should return same state', () => {
        const initialState = {
            serviceDependencies: apiServiceDependenciesData,
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
