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

import API from '../../api';
import MockApi from '../../mock/MockApi';

describe('test mockApi class', () => {
    let originalApi;
    beforeAll(() => {
        originalApi = API();
    });
    afterEach(() => {
        MockApi.cleanMockApi();
    });
    it('should be mock api', () => {
        const mockApi = {
            getPolicies: jest.fn(),
        };
        MockApi.setMockApi(mockApi);
        expect(API()).toEqual(mockApi);
    });
    it('should be original api', () => {
        const mockApi = {
            getPolicies: jest.fn(),
        };
        MockApi.setMockApi(mockApi);
        MockApi.cleanMockApi();
        expect(JSON.stringify(API())).toEqual(JSON.stringify(originalApi));
    });
});
