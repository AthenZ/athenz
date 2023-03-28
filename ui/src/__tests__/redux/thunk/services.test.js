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
import MockApi from '../../../mock/MockApi';
import sinon from 'sinon';
import { getExpiryTime } from '../../../redux/utils';
import { _ } from 'lodash';
import {
    loadingFailed,
    loadingInProcess,
    loadingSuccess,
} from '../../../redux/actions/loading';
import {
    addKey,
    addService,
    addServiceHost,
    allowProviderTemplate,
    deleteInstance,
    deleteKey,
    deleteService,
    getProvider,
    getServiceHeaderDetails,
    getServiceInstances,
    getServices,
} from '../../../redux/thunks/services';
import {
    addKeyToStore,
    addServiceHostToStore,
    addServiceToStore,
    allowProviderTemplateToStore,
    deleteKeyFromStore,
    deleteServiceFromStore,
    deleteServiceInstanceFromStore,
    loadInstancesToStore,
    loadProvidersToStore,
    loadServiceHeaderDetailsToStore,
    loadServices,
    returnServices,
} from '../../../redux/actions/services';
import { storeServices } from '../../../redux/actions/domains';
import {
    configStoreServices,
    singleApiService,
    singleStoreService,
} from '../config/service.test';

const serviceSelector = require('../../../redux/selectors/services');
const domainName = 'dom';
const utils = require('../../../redux/utils');

describe('getServices method', () => {
    beforeAll(() => {
        jest.spyOn(utils, 'getExpiryTime').mockReturnValue(5);
    });

    afterAll(() => {
        jest.spyOn(utils, 'getExpiryTime').mockRestore();
    });

    afterEach(() => {
        MockApi.cleanMockApi();
        jest.spyOn(utils, 'isExpired').mockRestore();
    });

    it('test getServices no data in the store', async () => {
        const getState = () => {
            return { services: {} };
        };
        MockApi.setMockApi({
            getServices: jest.fn().mockReturnValue(Promise.resolve([])),
        });
        const fakeDispatch = sinon.spy();
        await getServices(domainName)(fakeDispatch, getState);

        expect(
            _.isEqual(
                fakeDispatch.getCall(0).args[0],
                loadingInProcess('getServices')
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                loadServices({}, domainName, getExpiryTime())
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(2).args[0],
                loadingSuccess('getServices')
            )
        ).toBeTruthy();
    });

    it('test getServices dom exists in the store asked for dom and its not expired', async () => {
        jest.spyOn(utils, 'isExpired').mockReturnValue(false);
        const getState = () => {
            return { services: { domainName, expiry: getExpiryTime() } };
        };
        const fakeDispatch = sinon.spy();
        await getServices(domainName)(fakeDispatch, getState);
        expect(
            _.isEqual(fakeDispatch.getCall(0).args[0], returnServices())
        ).toBeTruthy();
    });

    it('test getServices dom exists in the store asked for dom but expired', async () => {
        jest.spyOn(utils, 'isExpired').mockReturnValue(true);
        const getState = () => {
            return { services: { domainName, expiry: getExpiryTime() } };
        };
        MockApi.setMockApi({
            getServices: jest.fn().mockReturnValue(Promise.resolve([])),
        });
        const fakeDispatch = sinon.spy();
        await getServices(domainName)(fakeDispatch, getState);

        expect(
            _.isEqual(
                fakeDispatch.getCall(0).args[0],
                loadingInProcess('getServices')
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                loadServices({}, domainName, getExpiryTime())
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(2).args[0],
                loadingSuccess('getServices')
            )
        ).toBeTruthy();
    });

    it('test getServices dom exists in the store asked for newDomain which not in the store', async () => {
        const servicesData = {
            domainName,
            expiry: getExpiryTime(),
            services: {},
        };
        const getState = () => {
            return {
                services: servicesData,
                domains: {},
            };
        };
        MockApi.setMockApi({
            getServices: jest.fn().mockReturnValue(Promise.resolve([])),
        });
        const fakeDispatch = sinon.spy();
        await getServices('newDomain')(fakeDispatch, getState);

        expect(
            _.isEqual(
                fakeDispatch.getCall(0).args[0],
                storeServices(servicesData)
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                loadingInProcess('getServices')
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(2).args[0],
                loadServices({}, 'newDomain', getExpiryTime())
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(3).args[0],
                loadingSuccess('getServices')
            )
        ).toBeTruthy();
    });

    it('test getServices dom exists in the store asked for newDomain which already in the store', async () => {
        jest.spyOn(utils, 'isExpired').mockReturnValue(false);
        const servicesData = {
            domainName,
            expiry: getExpiryTime(),
            services: {},
        };
        const services = {
            services: {},
            domainName: 'newDomain',
            expiry: getExpiryTime(),
        };
        const getState = () => {
            return {
                services: servicesData,
                domains: { newDomain: { services } },
            };
        };
        const fakeDispatch = sinon.spy();
        await getServices('newDomain')(fakeDispatch, getState);

        expect(
            _.isEqual(
                fakeDispatch.getCall(0).args[0],
                storeServices(servicesData)
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                loadServices({}, 'newDomain', services.expiry)
            )
        ).toBeTruthy();
    });
});

describe('addService method', () => {
    afterAll(() => {
        jest.spyOn(serviceSelector, 'thunkSelectServices').mockRestore();
    });
    afterEach(() => {
        MockApi.cleanMockApi();
    });

    it('get an error because serviceName already exists', async () => {
        jest.spyOn(serviceSelector, 'thunkSelectServices').mockReturnValue(
            configStoreServices
        );
        const fakeDispatch = sinon.spy();
        const getState = () => {
            return {
                services: { domainName: domainName },
            };
        };
        try {
            await addService(
                domainName,
                { name: 'service1' },
                'csrf'
            )(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e.statusCode).toBe(409);
            expect(e.body.message).toBe('Service service1 already exists');
        }

        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
    });

    it('successfully add service', async () => {
        jest.spyOn(serviceSelector, 'thunkSelectServices').mockReturnValue(
            configStoreServices
        );
        const getState = () => {
            return {
                services: { domainName: domainName },
            };
        };
        MockApi.setMockApi({
            addService: jest
                .fn()
                .mockReturnValue(Promise.resolve(singleApiService)),
        });
        const fakeDispatch = sinon.spy();

        await addService(
            domainName,
            { name: 'singleService' },
            'test'
        )(fakeDispatch, getState);

        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
        expect(fakeDispatch.getCall(1).args[0]).toEqual(
            addServiceToStore(singleStoreService)
        );
    });

    it('test getServices should fail to get from server', async () => {
        const getState = () => {
            return { services: {} };
        };
        const err = { statusCode: 400, body: { massage: 'failed' } };
        MockApi.setMockApi({
            getServices: jest.fn().mockReturnValue(Promise.reject(err)),
        });

        const fakeDispatch = sinon.spy();
        try {
            await getServices(domainName)(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(_.isEqual(e, err)).toBeTruthy();
            expect(
                _.isEqual(
                    fakeDispatch.getCall(0).args[0],
                    loadingInProcess('getServices')
                )
            ).toBeTruthy();
            expect(
                _.isEqual(
                    fakeDispatch.getCall(1).args[0],
                    loadingFailed('getServices', err)
                )
            ).toBeTruthy();
        }
    });
});

describe('deleteService method', () => {
    afterAll(() => {
        jest.spyOn(serviceSelector, 'thunkSelectServices').mockRestore();
    });
    afterEach(() => {
        MockApi.cleanMockApi();
    });

    it('get an error because serviceName doesnt exists', async () => {
        jest.spyOn(serviceSelector, 'thunkSelectServices').mockReturnValue({});
        const fakeDispatch = sinon.spy();
        const getState = () => {
            return {
                services: { domainName: domainName },
            };
        };
        try {
            await deleteService(
                domainName,
                'service1',
                'auditRef'
            )(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e.statusCode).toBe(404);
            expect(e.body.message).toBe('Service service1 doesnt exist');
        }

        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
    });

    it('successfully delete service', async () => {
        jest.spyOn(serviceSelector, 'thunkSelectServices').mockReturnValue({
            'dom.service1': {},
        });
        const getState = () => {
            return {
                services: { domainName: domainName },
            };
        };
        MockApi.setMockApi({
            deleteService: jest.fn().mockReturnValue(Promise.resolve(true)),
        });
        const fakeDispatch = sinon.spy();

        await deleteService(
            domainName,
            'service1',
            'test'
        )(fakeDispatch, getState);

        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                deleteServiceFromStore('dom.service1')
            )
        ).toBeTruthy();
    });
});

describe('deleteServiceInstance method', () => {
    afterAll(() => {
        jest.spyOn(
            serviceSelector,
            'selectInstancesWorkLoadData'
        ).mockRestore();
    });
    afterEach(() => {
        MockApi.cleanMockApi();
    });

    it('get an error because instance doesnt exists', async () => {
        let workLoadData = [
            {
                domainName: 'dom',
                serviceName: 'ows',
                uuid: '7982edfc-0b1b-4674-ad1c-55af492bd45d',
                ipAddresses: ['10.53.150.116', '2001:4998:efeb:283:0:0:0:236'],
                hostname: '7982edfc.dom.ne1.ows.oath.cloud',
                provider: 'sys.openstack.provider-classic',
                updateTime: '2022-08-01T18:00:40.240Z',
                certExpiryTime: '2022-08-31T00:42:58.000Z',
                certIssueTime: '2022-07-31T23:42:58.000Z',
            },
        ];
        jest.spyOn(
            serviceSelector,
            'selectInstancesWorkLoadData'
        ).mockReturnValue(workLoadData);
        const fakeDispatch = sinon.spy();
        const getState = () => {
            return {
                services: { domainName: domainName },
            };
        };
        try {
            await deleteInstance(
                'dynamic',
                'sys.openstack.provider-classic',
                'dom',
                'ows',
                '11111111-1111-1111-1111-111111111111',
                'auditRef',
                'csrf'
            )(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e.statusCode).toBe(404);
            expect(e.body.message).toBe(
                'Service Instance 11111111-1111-1111-1111-111111111111 doesnt exist'
            );
        }

        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
    });

    it('successfully delete service instance', async () => {
        let workLoadData = [
            {
                domainName: 'dom',
                serviceName: 'ows',
                uuid: '7982edfc-0b1b-4674-ad1c-55af492bd45d',
                ipAddresses: ['10.53.150.116', '2001:4998:efeb:283:0:0:0:236'],
                hostname: '7982edfc.dom.ne1.ows.oath.cloud',
                provider: 'sys.openstack.provider-classic',
                updateTime: '2022-08-01T18:00:40.240Z',
                certExpiryTime: '2022-08-31T00:42:58.000Z',
                certIssueTime: '2022-07-31T23:42:58.000Z',
            },
        ];
        jest.spyOn(
            serviceSelector,
            'selectInstancesWorkLoadData'
        ).mockReturnValue(workLoadData);
        const getState = () => {
            return {
                services: { domainName: domainName },
            };
        };
        MockApi.setMockApi({
            deleteInstance: jest.fn().mockReturnValue(Promise.resolve(true)),
        });
        const fakeDispatch = sinon.spy();

        await deleteInstance(
            'dynamic',
            'sys.openstack.provider-classic',
            'dom',
            'ows',
            '7982edfc-0b1b-4674-ad1c-55af492bd45d',
            'auditRef',
            'csrf'
        )(fakeDispatch, getState);

        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                deleteServiceInstanceFromStore(
                    'dom.ows',
                    '7982edfc-0b1b-4674-ad1c-55af492bd45d',
                    'dynamic'
                )
            )
        ).toBeTruthy();
    });
});

describe('deleteKey method', () => {
    afterAll(() => {
        jest.spyOn(serviceSelector, 'thunkSelectService').mockRestore();
    });
    afterEach(() => {
        MockApi.cleanMockApi();
    });

    it('get an error because key doesnt exist', async () => {
        jest.spyOn(serviceSelector, 'thunkSelectService').mockReturnValue({
            publicKeys: {},
        });
        const fakeDispatch = sinon.spy();
        const getState = () => {};

        try {
            await deleteKey(
                domainName,
                'service1',
                '1',
                'user'
            )(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e.statusCode).toBe(404);
            expect(e.body.message).toBe('Key id 1 doesnt exist');
        }

        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
    });

    it('successfully delete key', async () => {
        jest.spyOn(serviceSelector, 'thunkSelectService').mockReturnValue({
            publicKeys: { 1: {} },
        });
        const getState = () => {
            return {
                services: { domainName: domainName },
            };
        };
        MockApi.setMockApi({
            deleteKey: jest.fn().mockReturnValue(Promise.resolve(true)),
        });
        const fakeDispatch = sinon.spy();

        await deleteKey(
            domainName,
            'service1',
            '1',
            'user'
        )(fakeDispatch, getState);

        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                deleteKeyFromStore('dom.service1', '1')
            )
        ).toBeTruthy();
    });
});

describe('addKey method', () => {
    afterAll(() => {
        jest.spyOn(serviceSelector, 'thunkSelectService').mockRestore();
    });
    afterEach(() => {
        MockApi.cleanMockApi();
    });

    it('get an error because key already exists', async () => {
        jest.spyOn(serviceSelector, 'thunkSelectService').mockReturnValue({
            publicKeys: { 1: {} },
        });
        const fakeDispatch = sinon.spy();
        const getState = () => {};

        try {
            await addKey(
                domainName,
                'service1',
                '1',
                'value',
                'user'
            )(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e.statusCode).toBe(409);
            expect(e.body.message).toBe('Key id 1 already exists');
        }

        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
    });

    it('successfully add a key', async () => {
        jest.spyOn(serviceSelector, 'thunkSelectService').mockReturnValue({
            publicKeys: {},
        });
        const getState = () => {
            return {
                services: { domainName: domainName },
            };
        };
        MockApi.setMockApi({
            addKey: jest.fn().mockReturnValue(Promise.resolve(true)),
        });
        const fakeDispatch = sinon.spy();

        await addKey(
            domainName,
            'service1',
            '1',
            'value',
            'user'
        )(fakeDispatch, getState);

        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                addKeyToStore('dom.service1', '1', 'value')
            )
        ).toBeTruthy();
    });
});

describe('getProvider method', () => {
    afterAll(() => {
        jest.spyOn(serviceSelector, 'thunkSelectService').mockRestore();
    });
    afterEach(() => {
        MockApi.cleanMockApi();
    });

    it('get the provider from the backend', async () => {
        jest.spyOn(serviceSelector, 'thunkSelectService').mockReturnValue({
            provider: {},
        });
        let myMockApi = {
            getProvider: jest
                .fn()
                .mockReturnValue(
                    Promise.resolve({ provider: {}, allProviders: [] })
                ),
        };
        MockApi.setMockApi(myMockApi);
        sinon.spy(myMockApi, 'getProvider');
        const fakeDispatch = sinon.spy();
        const getState = () => {};
        await getProvider(domainName, 'service1')(fakeDispatch, getState);
        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
        expect(
            myMockApi.getProvider.getCall(0).calledWith(domainName, 'service1')
        ).toBeTruthy();
        expect(fakeDispatch.getCall(1).args[0]).toEqual(
            loadProvidersToStore('dom.service1', {}, [])
        );
    });

    it('get return the provider because it exists in the store', async () => {
        jest.spyOn(serviceSelector, 'thunkSelectService').mockReturnValue({
            provider: { expiry: getExpiryTime() },
        });
        let myMockApi = {
            getProvider: jest.fn().mockReturnValue(Promise.resolve(true)),
        };
        MockApi.setMockApi(myMockApi);
        sinon.spy(myMockApi, 'getProvider');
        jest.spyOn(utils, 'isExpired').mockReturnValue(false);
        const fakeDispatch = sinon.spy();
        const getState = () => {};
        await getProvider(domainName, 'service1')(fakeDispatch, getState);
        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
        expect(myMockApi.getProvider.getCall(0)).toBeNull();
        expect(fakeDispatch.getCall(1)).toBeNull();
    });
});

describe('allowProviderTemplate method', () => {
    afterEach(() => {
        MockApi.cleanMockApi();
    });

    it('allow provider', async () => {
        const fakeDispatch = sinon.spy();
        const getState = () => {};
        let myMockApi = {
            allowProviderTemplate: jest.fn().mockReturnValue(true),
        };
        MockApi.setMockApi(myMockApi);
        sinon.spy(myMockApi, 'allowProviderTemplate');
        await allowProviderTemplate(
            domainName,
            'service1',
            '1',
            'user'
        )(fakeDispatch, getState);
        expect(fakeDispatch.getCall(0)).toBeTruthy();
        expect(
            myMockApi.allowProviderTemplate
                .getCall(0)
                .calledWith(domainName, 'service1', '1', 'user')
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                allowProviderTemplateToStore('dom.service1', '1')
            )
        ).toBeTruthy();
    });
});

describe('getServiceInstances method', () => {
    afterEach(() => {
        MockApi.cleanMockApi();
        jest.spyOn(serviceSelector, 'thunkSelectService').mockRestore();
    });
    it('load instance successfully', async () => {
        const fakeDispatch = sinon.spy();
        const getState = () => {};
        let myMockApi = {
            getInstances: jest.fn().mockReturnValue({ name: 'instance' }),
        };
        jest.spyOn(serviceSelector, 'thunkSelectService').mockReturnValue({
            name: domainName + '.service1',
        });
        MockApi.setMockApi(myMockApi);
        sinon.spy(myMockApi, 'getInstances');
        await getServiceInstances(
            domainName,
            'service1',
            'dynamic'
        )(fakeDispatch, getState);
        expect(
            myMockApi.getInstances
                .getCall(0)
                .calledWith(domainName, 'service1', 'dynamic')
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(0).args[0],
                loadInstancesToStore('dom.service1', 'dynamic', {
                    name: 'instance',
                })
            )
        ).toBeTruthy();
    });
});

describe('getServiceHeaderDetails method', () => {
    afterEach(() => {
        MockApi.cleanMockApi();
        jest.spyOn(serviceSelector, 'thunkSelectService').mockRestore();
    });

    it('load service header successfully', async () => {
        const fakeDispatch = sinon.spy();
        const getState = () => {};
        let myMockApi = {
            getServiceHeaderDetails: jest
                .fn()
                .mockReturnValue({ data: 'serviceHeaderData' }),
        };
        MockApi.setMockApi(myMockApi);
        jest.spyOn(serviceSelector, 'thunkSelectService').mockReturnValue({
            name: domainName + '.service1',
        });
        sinon.spy(myMockApi, 'getServiceHeaderDetails');
        await getServiceHeaderDetails(domainName, 'service1')(
            fakeDispatch,
            getState
        );
        expect(
            myMockApi.getServiceHeaderDetails.getCall(0).calledWith()
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(0).args[0],
                loadServiceHeaderDetailsToStore('dom.service1', {
                    data: 'serviceHeaderData',
                })
            )
        ).toBeTruthy();
    });
    it('get an error while load service header', async () => {
        const fakeDispatch = sinon.spy();
        const getState = () => {};
        let myMockApi = {
            getServiceHeaderDetails: jest.fn().mockImplementation(() => {
                throw {
                    statusCode: 400,
                    body: { message: 'cant get the header data' },
                };
            }),
        };
        MockApi.setMockApi(myMockApi);
        jest.spyOn(serviceSelector, 'thunkSelectService').mockReturnValue({
            name: domainName + '.service1',
        });
        sinon.spy(myMockApi, 'getServiceHeaderDetails');
        try {
            await getServiceHeaderDetails(domainName, 'service1')(
                fakeDispatch,
                getState
            );
            fail();
        } catch (e) {
            expect(e.statusCode).toBe(400);
            expect(e.body.message).toBe('cant get the header data');
        }
        expect(
            myMockApi.getServiceHeaderDetails.getCall(0).calledWith()
        ).toBeTruthy();
    });
});

describe('addServiceHost method', () => {
    beforeAll(() => {
        jest.spyOn(utils, 'getCurrentTime').mockReturnValue(5);
    });

    afterAll(() => {
        jest.spyOn(utils, 'getCurrentTime').mockRestore();
    });
    afterEach(() => {
        MockApi.cleanMockApi();
    });

    it('add service host successfully', async () => {
        const fakeDispatch = sinon.spy();
        const instances = {
            workLoadData: [
                {
                    domainName: 'dom',
                    serviceName: 'ows',
                    type: 'EXTERNAL_APPLIANCE',
                    ipAddresses: ['101.101.101.2'],
                    name: '101.101.101.2',
                    updateTime: '2022-08-03T11:07:02.416Z',
                },
            ],
            workLoadMeta: {
                totalDynamic: 0,
                totalStatic: 2,
                totalRecords: 2,
                totalHealthyDynamic: 0,
            },
        };
        const getState = () => {};
        let myMockApi = {
            addServiceHost: jest.fn().mockReturnValue({ data: 'host' }),
            getInstances: jest.fn().mockReturnValue(instances),
        };
        MockApi.setMockApi(myMockApi);
        sinon.spy(myMockApi, 'addServiceHost');
        await addServiceHost(
            domainName,
            'service1',
            { name: 'host' },
            'auditRef',
            'csrf'
        )(fakeDispatch, getState);
        expect(
            myMockApi.addServiceHost.getCall(0).firstArg === domainName
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(0).args[0],
                loadInstancesToStore('dom.service1', 'static', instances)
            )
        ).toBeTruthy();
    });
});
