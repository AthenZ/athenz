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
jest.mock('../../server/services/userService');

const clients = require('../../server/clients');
const MOCK_FILE_INFO = {
    'data/users.json':
        '[{"is_human": 1, "login": "testuser", "gecos":"full name", "enabled_status": 1}]',
};
const config = {
    zms: 'test',
    userFilePath: 'data',
    userFileName: 'users.json',
    msd: 'test',
    ums: 'test',
    zts: 'test',
    cloud_sso: 'test',
};

describe('clients test', () => {
    beforeAll(() => {
        require('fs').__setMockFiles(MOCK_FILE_INFO);
    });
    test('should be able to register clients', () => {
        clients.load(config, {}).catch((err) => {
            expect(err).toBeNull();
        });
    });
    test('should create request scoped clients in middleware', async () => {
        await clients.load(config, {});

        const req = { authHeader: 'Athenz-Principal-Auth' };
        const next = jest.fn();
        clients.middleware()(req, {}, next);

        expect(next).toHaveBeenCalledTimes(1);
        ['zms', 'msd', 'zts', 'ums', 'cloud_sso'].forEach((name) => {
            expect(req.clients[name]).toBeDefined();
            expect(req.clients[name].request).toBe(req);
            expect(Object.keys(req.clients[name].headers)).toEqual([
                'cookie',
                'Athenz-Principal-Auth',
            ]);
        });
    });
});
