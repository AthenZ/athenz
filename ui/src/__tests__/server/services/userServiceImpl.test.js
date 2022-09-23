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
'use strict';

jest.mock('fs');
const userServiceImpl = require('../../../server/services/userServiceImpl');
const MOCK_FILE_INFO = {
    'data/users.json':
        '[{"is_human": 1, "login": "testuser", "gecos":"full name", "enabled_status": 1}]',
};

describe('userServiceImpl test', () => {
    beforeAll(() => {
        require('fs').__setMockFiles(MOCK_FILE_INFO);
    });
    test('should return users from file', () => {
        userServiceImpl.fetchUpdatedUsers('data', 'users.json').then((data) => {
            expect(data).not.toBeNull();
        });
    });
    test('should fail fetch on invalid file', () => {
        userServiceImpl
            .fetchUpdatedUsers('data', 'users1.json')
            .catch((err) => {
                expect(err).not.toBeNull();
            });
    });
    test('should check user update', () => {
        userServiceImpl.checkUsersUpdate('data', 'users.json').then((size) => {
            expect(size).toEqual(15);
        });
    });
    test('should fail user update on invalid file', () => {
        userServiceImpl
            .checkUsersUpdate('data', 'users1.json')
            .then((message) => {
                expect(message).not.toBeNull();
            });
    });
});
