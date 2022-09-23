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
import { _ } from 'lodash';
import {
    LOADING_FAILED,
    LOADING_IN_PROCESS,
    LOADING_SUCCESS,
} from '../../../redux/actions/loading';
import { loading } from '../../../redux/reducers/loading';

describe('Loading Reducer', () => {
    it('should load the func name in', () => {
        const initialState = [];
        const action = {
            type: LOADING_IN_PROCESS,
            payload: {
                funcName: 'getPolicies',
            },
        };
        const expectedState = ['getPolicies'];
        const newState = loading(initialState, action);
        expect(newState).toEqual(expectedState);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should remove func from state due success', () => {
        const initialState = ['getPolicies', 'getRoles'];
        const action = {
            type: LOADING_SUCCESS,
            payload: {
                funcName: 'getRoles',
            },
        };
        const expectedState = ['getPolicies'];
        const newState = loading(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should remove func from state due failed', () => {
        const initialState = ['getPolicies', 'getRoles'];
        const action = {
            type: LOADING_FAILED,
            payload: {
                funcName: 'getRoles',
            },
        };
        const expectedState = ['getPolicies'];
        const newState = loading(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
});
