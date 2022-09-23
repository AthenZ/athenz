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
import sinon from 'sinon';
import { expiry } from '../../config/config.test';
import MockApi from '../../../mock/MockApi';
import { getServiceDependencies } from '../../../redux/thunks/visibility';
import {
    loadingFailed,
    loadingInProcess,
    loadingSuccess,
} from '../../../redux/actions/loading';
import {
    loadServiceDependencies,
    returnServiceDependencies,
} from '../../../redux/actions/visibility';
import { _ } from 'lodash';
import { getExpiryTime } from '../../../redux/utils';
import { storeServiceDependencies } from '../../../redux/actions/domains';

describe('test getServiceDependencies thunk', () => {
    const domainName = 'dom';
    const utils = require('../../../redux/utils');

    beforeAll(() => {
        jest.spyOn(utils, 'getExpiryTime').mockReturnValue(expiry);
    });

    afterAll(() => {
        jest.spyOn(utils, 'getExpiryTime').mockRestore();
    });

    afterEach(() => {
        MockApi.cleanMockApi();
        jest.spyOn(utils, 'isExpired').mockRestore();
    });

    it('test getServiceDependencies new domain without current domain scenario', async () => {
        const getState = () => {
            return { serviceDependencies: [] };
        };
        MockApi.setMockApi({
            getServiceDependencies: jest
                .fn()
                .mockReturnValue(Promise.resolve([])),
        });
        const fakeDispatch = sinon.spy();
        await getServiceDependencies(domainName)(fakeDispatch, getState);

        expect(
            _.isEqual(
                fakeDispatch.getCall(0).args[0],
                loadingInProcess('getServiceDependencies')
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                loadServiceDependencies([], domainName, getExpiryTime())
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(2).args[0],
                loadingSuccess('getServiceDependencies')
            )
        ).toBeTruthy();
    });

    it('test getServiceDependencies new domain with current domain scenario', async () => {
        const serviceDependenciesData = {
            domainName,
            expiry: getExpiryTime(),
            serviceDependencies: [],
        };
        const getState = () => {
            return {
                serviceDependencies: serviceDependenciesData,
                domains: {},
            };
        };
        MockApi.setMockApi({
            getServiceDependencies: jest
                .fn()
                .mockReturnValue(Promise.resolve([])),
        });
        const fakeDispatch = sinon.spy();
        await getServiceDependencies('newDomain')(fakeDispatch, getState);

        expect(
            _.isEqual(
                fakeDispatch.getCall(0).args[0],
                storeServiceDependencies(serviceDependenciesData)
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                loadingInProcess('getServiceDependencies')
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(2).args[0],
                loadServiceDependencies([], 'newDomain', getExpiryTime())
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(3).args[0],
                loadingSuccess('getServiceDependencies')
            )
        ).toBeTruthy();
    });

    it('test getServiceDependencies current domain scenario', async () => {
        jest.spyOn(utils, 'isExpired').mockReturnValue(false);
        const getState = () => {
            return {
                serviceDependencies: { domainName, expiry: getExpiryTime() },
            };
        };
        const fakeDispatch = sinon.spy();
        await getServiceDependencies(domainName)(fakeDispatch, getState);
        expect(
            _.isEqual(
                fakeDispatch.getCall(0).args[0],
                returnServiceDependencies()
            )
        ).toBeTruthy();
    });

    it('test getServiceDependencies current domain expired scenario', async () => {
        jest.spyOn(utils, 'isExpired').mockReturnValue(true);
        const getState = () => {
            return {
                serviceDependencies: { domainName, expiry: getExpiryTime() },
            };
        };
        MockApi.setMockApi({
            getServiceDependencies: jest
                .fn()
                .mockReturnValue(Promise.resolve([])),
        });
        const fakeDispatch = sinon.spy();
        await getServiceDependencies(domainName)(fakeDispatch, getState);

        expect(
            _.isEqual(
                fakeDispatch.getCall(0).args[0],
                loadingInProcess('getServiceDependencies')
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                loadServiceDependencies([], domainName, getExpiryTime())
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(2).args[0],
                loadingSuccess('getServiceDependencies')
            )
        ).toBeTruthy();
    });

    it('test getServiceDependencies new domain already in the store scenario', async () => {
        jest.spyOn(utils, 'isExpired').mockReturnValue(false);
        const newDomain = 'newDomain';
        const serviceDependenciesData = {
            domainName: newDomain,
            expiry: getExpiryTime(),
            serviceDependencies: [],
        };
        const serviceDependencies = {
            serviceDependencies: [],
            domainName,
            expiry: getExpiryTime(),
        };
        const getState = () => {
            return {
                serviceDependencies,
                domains: {
                    newDomain: { serviceDependencies: serviceDependenciesData },
                },
            };
        };
        MockApi.setMockApi({
            getServiceDependencies: jest
                .fn()
                .mockReturnValue(Promise.resolve([])),
        });
        const fakeDispatch = sinon.spy();
        await getServiceDependencies('newDomain')(fakeDispatch, getState);

        expect(
            _.isEqual(
                fakeDispatch.getCall(0).args[0],
                storeServiceDependencies(serviceDependencies)
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                loadServiceDependencies(
                    serviceDependenciesData.serviceDependencies,
                    newDomain,
                    getExpiryTime()
                )
            )
        ).toBeTruthy();
    });
    it('test getServiceDependencies should fail to get from server', async () => {
        const getState = () => {
            return { serviceDependencies: [] };
        };
        const err = { statusCode: 400, body: { massage: 'failed' } };
        MockApi.setMockApi({
            getServiceDependencies: jest
                .fn()
                .mockReturnValue(Promise.reject(err)),
        });
        const fakeDispatch = sinon.spy();
        try {
            await getServiceDependencies(domainName)(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(_.isEqual(e, err)).toBeTruthy();
            expect(
                _.isEqual(
                    fakeDispatch.getCall(0).args[0],
                    loadingInProcess('getServiceDependencies')
                )
            ).toBeTruthy();
            expect(
                _.isEqual(
                    fakeDispatch.getCall(1).args[0],
                    loadingFailed('getServiceDependencies')
                )
            ).toBeTruthy();
        }
    });
});
