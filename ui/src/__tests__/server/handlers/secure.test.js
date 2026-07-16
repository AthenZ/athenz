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

let secure = require('../../../server/handlers/secure');
const cookieSession = require('cookie-session');
const request = require('supertest');
const express = require('express');
let expressApp = express();
expressApp.get('/test', async (req, res) => {
    res.json({ message: 'pass!' });
});
let appConfig = require('../../../config/config')();

jest.mock('cookie-session', () => jest.fn(() => (req, res, next) => next()));

describe('secure test', () => {
    beforeEach(() => {
        cookieSession.mockClear();
    });

    describe('middleware registration test', () => {
        test('should register all security middlewares', () => {
            const app = {};
            app.use = jest.fn();
            secure(app, {}, { cookieSession: '1234' });
            expect(app.use).toHaveBeenCalledTimes(8);
        });
    });

    describe('session cookie maxAge configuration', () => {
        const SESSION_COOKIE_MAX_AGE_DEFAULT = 30 * 60 * 1000;

        test('should use configured sessionCookieMaxAge when provided', () => {
            const app = { use: jest.fn() };
            const customMaxAge = 60 * 60 * 1000; // 1 hour
            secure(app, { sessionCookieMaxAge: customMaxAge }, { cookieSession: '1234' });
            expect(cookieSession).toHaveBeenCalledWith(
                expect.objectContaining({ maxAge: customMaxAge })
            );
        });

        test('should default to 30 minutes when sessionCookieMaxAge is absent', () => {
            const app = { use: jest.fn() };
            secure(app, {}, { cookieSession: '1234' });
            expect(cookieSession).toHaveBeenCalledWith(
                expect.objectContaining({ maxAge: SESSION_COOKIE_MAX_AGE_DEFAULT })
            );
        });

        test('should default to 30 minutes when sessionCookieMaxAge is 0', () => {
            const app = { use: jest.fn() };
            secure(app, { sessionCookieMaxAge: 0 }, { cookieSession: '1234' });
            expect(cookieSession).toHaveBeenCalledWith(
                expect.objectContaining({ maxAge: SESSION_COOKIE_MAX_AGE_DEFAULT })
            );
        });
    });

    describe('middleware calls test', () => {
        beforeAll(() => {
            secure(expressApp, appConfig, { cookieSession: '1234' });
        });
        test('should call CSP middleware', async () => {
            await request(expressApp)
                .get('/test')
                .then((res) => {
                    expect(res.statusCode).toEqual(200);
                });
        });
    });
});
