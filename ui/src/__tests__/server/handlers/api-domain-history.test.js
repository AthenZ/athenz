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

const api = require('../../../server/handlers/api');
const sinon = require('sinon');
const CLIENTS = require('../../../server/clients');

const config = {
    zms: 'https://zms.athenz.io',
    athenzDomainService: 'athenz.unit-test',
    headerLinks: [],
    allProviders: [
        {
            id: 'aws_instance_launch_provider',
            name: 'AWS EC2/EKS/Fargate launches instances for the service',
        },
    ],
    createDomainMessage: '',
    servicePageConfig: '',
    productMasterLink: '',
    userData: () => {},
    serviceHeaderLinks: [],
};
const secrets = {};
const expressApp = require('express')();
const request = require('supertest');
const bodyParser = require('body-parser');

describe('Fetchr Server API Test', () => {
    describe('success tests', () => {
        beforeAll(() => {
            sinon.stub(CLIENTS, 'load').returns(Promise.resolve());
            sinon.stub(CLIENTS, 'middleware').returns((req, res, next) => {
                req.clients = {
                    zms: {},
                };
                next();
            });
            api.load(config, secrets).then(() => {
                expressApp.use(bodyParser.urlencoded({ extended: false }));
                expressApp.use(bodyParser.json());
                expressApp.use((req, res, next) => {
                    req.session = {
                        shortId: 'testuser',
                    };
                    req.csrfToken = () => '1234';
                    next();
                });
                api.route(expressApp);
            });
        });
        afterAll(() => {
            CLIENTS.load.restore();
            CLIENTS.middleware.restore();
        });
        it('get domain history test success', async () => {
            await request(expressApp)
                .get('/api/v1/domain-history')
                .then((res) => {
                    expect(res.body).toEqual([
                        {
                            action: 'action',
                            who: 'principal',
                            whoFull: 'principal full',
                            whatEntity: 'resource',
                            when: '2020-01-01T10:00:00.000Z',
                            details: 'detailed json',
                            epoch: 'epoch timestamp',
                            why: 'justification',
                        },
                    ]);
                });
        });
    });
});
