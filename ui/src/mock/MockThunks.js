/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

const thunkRoles = require('../redux/thunks/roles');
const thunkPolicies = require('../redux/thunks/policies');
const thunkServices = require('../redux/thunks/domains');
const thunkDomainData = require('../redux/thunks/domain');
const thunkDomains = require('../redux/thunks/domains');
const thunkUser = require('../redux/thunks/user');

export class MockThunks {
    mockAllThunks() {
        jest.mock('../redux/thunks/domain', () => {
            return jest.fn(() => {
                return {
                    type: 'mock',
                };
            });
        });
        jest.mock('../redux/thunks/domains', () => {
            return jest.fn(() => {
                return {
                    type: 'mock',
                };
            });
        });
        jest.mock('../redux/thunks/policies', () => {
            return jest.fn(() => {
                return {
                    type: 'mock',
                };
            });
        });
    }
}
