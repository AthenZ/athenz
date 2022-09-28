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

// import 'setimmediate';
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
};
const secrets = {};
const expressApp = require('express')();
const request = require('supertest');
const bodyParser = require('body-parser');

describe('policy tests', () => {
    beforeEach(() => {
        sinon.stub(CLIENTS, 'load').returns(Promise.resolve());
        sinon.stub(CLIENTS, 'middleware').returns((req, res, next) => {
            req.clients = {
                zms: {
                    getPolicy: (params, callback) =>
                        params.fail
                            ? callback(undefined, {})
                            : callback({ status: 404 }, null),
                    putPolicy: (params, callback) =>
                        params.forcefail
                            ? callback({ status: 404 }, null)
                            : callback(undefined, { success: 'true' }),
                },
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
    afterEach(() => {
        CLIENTS.load.restore();
        CLIENTS.middleware.restore();
    });
    it('createPolicy test success', async () => {
        await request(expressApp)
            .post('/api/v1')
            .send({
                requests: {
                    g0: {
                        resource: 'policy',
                        operation: 'create',
                        params: {
                            domainName: 'test',
                            policyName: 'dummyPol',
                        },
                    },
                },
            })
            .set('Accept', 'application/json')
            .set('Content-Type', 'application/json')
            .then((res) => {
                expect(res.body.g0.data).toEqual({ success: 'true' });
            });
    });
    it('createPolicy test fail', async () => {
        await request(expressApp)
            .post('/api/v1')
            .send({
                requests: {
                    g0: {
                        resource: 'policy',
                        operation: 'create',
                        params: {
                            domainName: 'test',
                            policyName: 'dummyPol',
                            fail: 'yes',
                        },
                    },
                },
            })
            .set('Accept', 'application/json')
            .set('Content-Type', 'application/json')
            .then((res) => {
                expect(res.status).toEqual(500);
                expect(res.error.text).toEqual(
                    '{"message":"Policy dummyPol exists in domain test."}'
                );
            });
    });
});
