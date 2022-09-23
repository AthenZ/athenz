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

const status = require('../../../server/handlers/status');
const request = require('supertest');
const express = require('express');
let expressApp;

describe('status handler test', () => {
    describe('status handler 404', () => {
        beforeAll(() => {
            expressApp = express();
            status(expressApp, {
                akamaiPath: '',
                statusPath: '',
            });
        });
        test('should register all status handlers correctly', () => {
            const app = {};
            app.get = jest.fn();
            status(app);
            expect(app.get).toHaveBeenCalledTimes(4);
        });
        test('should return 404 for /akamai', async () => {
            const response = await request(expressApp).get('/akamai');
            expect(response.statusCode).toBe(404);
        });
        test('should return 404 for /status', async () => {
            const response = await request(expressApp).get('/status');
            expect(response.statusCode).toBe(404);
        });
        test('should return 404 for /status.html', async () => {
            const response = await request(expressApp).get('/status.html');
            expect(response.statusCode).toBe(404);
        });
    });
    describe('status handler 200', () => {
        beforeAll(() => {
            expressApp = express();
            status(expressApp, {
                akamaiPath: '',
                statusPath: '',
            });
        });
        test('should return 200 for /autherror', async () => {
            const response = await request(expressApp).get('/autherror');
            expect(response.statusCode).toBe(200);
        });
    });
});
