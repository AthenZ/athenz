/*
 * Copyright 2020 Verizon Media
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

const logger = require('../../../server/handlers/logger');
const expressApp = require('express')();
const request = require('supertest');

describe('logger middleware test', () => {
    test('should add logger middleware', () => {
        let app = {};
        app.use = jest.fn();
        logger(app);
        expect(app.use).toHaveBeenCalled();
    });
    test('should execute middleware as expected', async () => {
        expressApp.get('/ping', (req, res) => res.status(200).send('pong'));
        logger(expressApp);
        await request(expressApp).get('/ping').then(res => {
            expect(res.status).toEqual(200);
        });
    });
});
