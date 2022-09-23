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
