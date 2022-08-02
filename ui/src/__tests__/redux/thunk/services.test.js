import MockApi from '../../../mock/MockApi';
import sinon from 'sinon';
import { getExpiryTime } from '../../../redux/utils';
import { _ } from 'lodash';
import {
    loadingInProcess,
    loadingSuccess,
} from '../../../redux/actions/loading';
import {
    addKey,
    allowProviderTemplate,
    deleteKey,
    deleteService,
    getProvider,
    getServices,
} from '../../../redux/thunks/services';
import {
    addKeyToStore,
    allowProviderTemplateToStore,
    deleteKeyFromStore,
    deleteServiceFromStore,
    loadProvidersToStore,
    loadServices,
    returnServices,
} from '../../../redux/actions/services';
import { storeServices } from '../../../redux/actions/domains';

const servicesThunk = require('../../../redux/thunks/services');
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

describe('deleteService method', () => {
    beforeAll(() => {
        jest.spyOn(servicesThunk, 'getServices').mockReturnValue(true);
    });
    afterAll(() => {
        jest.spyOn(servicesThunk, 'getServices').mockRestore();
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

describe('deleteKey method', () => {
    beforeAll(() => {
        jest.spyOn(servicesThunk, 'getServices').mockReturnValue(true);
    });
    afterAll(() => {
        jest.spyOn(servicesThunk, 'getServices').mockRestore();
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
    beforeAll(() => {
        jest.spyOn(servicesThunk, 'getServices').mockReturnValue(true);
    });
    afterAll(() => {
        jest.spyOn(servicesThunk, 'getServices').mockRestore();
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

// TODO roy - check why if we swith the tests it fails
describe('getProvider method', () => {
    beforeAll(() => {
        jest.spyOn(servicesThunk, 'getServices').mockReturnValue(true);
    });
    afterAll(() => {
        jest.spyOn(servicesThunk, 'getServices').mockRestore();
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
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                loadProvidersToStore('dom.service1', {}, [])
            )
        ).toBeTruthy();
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
    beforeAll(() => {
        jest.spyOn(servicesThunk, 'getProvider').mockReturnValue(true);
    });
    afterAll(() => {
        jest.spyOn(servicesThunk, 'getProvider').mockRestore();
    });
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
