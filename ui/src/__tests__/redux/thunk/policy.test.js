import MockApi from '../../../mock/MockApi';
import sinon from 'sinon';
import { getExpiryTime } from '../../../redux/utils';
import {
    addAssertion,
    addAssertionConditions,
    addAssertionPolicyVersion,
    deleteAssertion,
    deleteAssertionCondition,
    deleteAssertionConditions,
    deleteAssertionPolicyVersion,
    deletePolicy,
    deletePolicyVersion,
    getPolicies,
    setActivePolicyVersion,
} from '../../../redux/thunks/policies';
import { _ } from 'lodash';
import {
    getAddAssertionPolicyVersionAction,
    getDeleteAssertionPolicyVersionAction,
    getLoadPoliciesAction,
    getStorePoliciesAction,
} from '../../../tests_utils/thunkUtils';
import {
    addAssertionConditionsToStore,
    deleteAssertionConditionFromStore,
    deleteAssertionConditionsFromStore,
    deletePolicyFromStore,
    deletePolicyVersionFromStore,
    returnPolicies,
    setActivePolicyVersionToStore,
} from '../../../redux/actions/policies';
import {
    apiAssertion,
    apiAssertionConditions,
    singleStorePolicy,
    singleStorePolicyWithAssertionConditions,
} from '../../config/config.test';
import { getPolicyFullName } from '../../../redux/thunks/utils/policies';
import {
    loadingInProcess,
    loadingSuccess,
} from '../../../redux/actions/loading';

const policiesSelectors = require('../../../redux/selectors/policies');

describe('test getPolicies thunk', () => {
    const domainName = 'dom';
    const utils = require('../../../redux/utils');

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

    it('test getPolicies new domain without current domain scenario', async () => {
        const getState = () => {
            return { policies: {} };
        };
        MockApi.setMockApi({
            getPolicies: jest.fn().mockReturnValue(Promise.resolve([])),
        });
        const fakeDispatch = sinon.spy();
        await getPolicies(domainName)(fakeDispatch, getState);

        expect(
            _.isEqual(
                fakeDispatch.getCall(0).args[0],
                loadingInProcess('getPolicies')
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                getLoadPoliciesAction(domainName)
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(2).args[0],
                loadingSuccess('getPolicies')
            )
        ).toBeTruthy();
    });

    it('test getPolicies new domain with current domain scenario', async () => {
        const policiesData = {
            domainName,
            expiry: getExpiryTime(),
            policies: {},
        };
        const getState = () => {
            return { policies: policiesData, domains: {} };
        };
        MockApi.setMockApi({
            getPolicies: jest.fn().mockReturnValue(Promise.resolve([])),
        });
        const fakeDispatch = sinon.spy();
        await getPolicies('newDomain')(fakeDispatch, getState);

        expect(
            _.isEqual(
                fakeDispatch.getCall(0).args[0],
                getStorePoliciesAction(policiesData)
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                loadingInProcess('getPolicies')
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(2).args[0],
                getLoadPoliciesAction('newDomain')
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(3).args[0],
                loadingSuccess('getPolicies')
            )
        ).toBeTruthy();
    });

    it('test getPolicies current domain scenario', async () => {
        jest.spyOn(utils, 'isExpired').mockReturnValue(false);
        const getState = () => {
            return { policies: { domainName, expiry: getExpiryTime() } };
        };
        const fakeDispatch = sinon.spy();
        await getPolicies(domainName)(fakeDispatch, getState);
        expect(
            _.isEqual(fakeDispatch.getCall(0).args[0], returnPolicies())
        ).toBeTruthy();
    });

    it('test getPolicies current domain expired scenario', async () => {
        jest.spyOn(utils, 'isExpired').mockReturnValue(true);
        const getState = () => {
            return { policies: { domainName, expiry: getExpiryTime() } };
        };
        MockApi.setMockApi({
            getPolicies: jest.fn().mockReturnValue(Promise.resolve([])),
        });
        const fakeDispatch = sinon.spy();
        await getPolicies(domainName)(fakeDispatch, getState);

        expect(
            _.isEqual(
                fakeDispatch.getCall(0).args[0],
                loadingInProcess('getPolicies')
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                getLoadPoliciesAction(domainName)
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(2).args[0],
                loadingSuccess('getPolicies')
            )
        ).toBeTruthy();
    });

    it('test getPolicies new domain already in the store scenario', async () => {
        jest.spyOn(utils, 'isExpired').mockReturnValue(false);
        const policiesData = {
            domainName,
            expiry: getExpiryTime(),
            policies: {},
        };
        const newDomain = 'newDomain';
        const policies = {
            policies: {},
            domainName: newDomain,
            expiry: getExpiryTime(),
        };
        const getState = () => {
            return {
                policies: policiesData,
                domains: { newDomain: { policies } },
            };
        };
        MockApi.setMockApi({
            getPolicies: jest.fn().mockReturnValue(Promise.resolve([])),
        });
        const fakeDispatch = sinon.spy();
        await getPolicies('newDomain')(fakeDispatch, getState);

        expect(
            _.isEqual(
                fakeDispatch.getCall(0).args[0],
                getStorePoliciesAction(policiesData)
            )
        ).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                getLoadPoliciesAction(newDomain)
            )
        ).toBeTruthy();
    });
});

describe('test deletePolicy thunk', () => {
    const domainName = 'dom';
    const policyName = 'singlePolicy';
    const getState = () => {};

    afterEach(() => {
        jest.spyOn(policiesSelectors, 'selectPolicyThunk').mockRestore();
        MockApi.cleanMockApi();
    });

    it('should delete policy successfully', async () => {
        const fakeDispatch = sinon.spy();
        MockApi.setMockApi({
            deletePolicy: jest.fn().mockReturnValue(Promise.resolve(true)),
        });
        jest.spyOn(policiesSelectors, 'selectPolicyThunk').mockReturnValue(
            singleStorePolicy
        );
        const deletePolicyAction = deletePolicyFromStore(
            getPolicyFullName(domainName, policyName)
        );

        await deletePolicy(domainName, policyName)(fakeDispatch, getState);

        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
        expect(
            _.isEqual(fakeDispatch.getCall(1).args[0], deletePolicyAction)
        ).toBeTruthy();
    });

    it("should throw err, policy doesn't exists in store", async () => {
        jest.spyOn(policiesSelectors, 'selectPolicyThunk').mockReturnValue(
            null
        );
        MockApi.setMockApi({
            deletePolicy: jest.fn().mockReturnValue(Promise.resolve(true)),
        });
        const fakeDispatch = sinon.spy();
        try {
            await deletePolicy(domainName, policyName)(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e.statusCode).toBe(404);
        }
    });

    it('should throw err from server', async () => {
        jest.spyOn(policiesSelectors, 'selectPolicyThunk').mockReturnValue(
            singleStorePolicy
        );
        MockApi.setMockApi({
            deletePolicy: jest
                .fn()
                .mockReturnValue(
                    Promise.reject({ body: { message: 'failed' } })
                ),
        });
        const fakeDispatch = sinon.spy();
        try {
            await deletePolicy(domainName, policyName)(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e.body.message === 'failed').toBeTruthy();
        }
    });
});

describe('test deletePolicyVersion thunk', () => {
    const domainName = 'dom';
    const policyName = 'singlePolicy';
    const version = '0';
    const getState = () => {};

    afterEach(() => {
        jest.spyOn(policiesSelectors, 'selectPolicyVersionThunk').mockRestore();
        MockApi.cleanMockApi();
    });

    it('should delete policy version successfully', async () => {
        const fakeDispatch = sinon.spy();
        jest.spyOn(
            policiesSelectors,
            'selectPolicyVersionThunk'
        ).mockReturnValue(singleStorePolicy);
        MockApi.setMockApi({
            deletePolicyVersion: jest
                .fn()
                .mockReturnValue(Promise.resolve(true)),
        });
        const deletePolicyAction = deletePolicyVersionFromStore(
            getPolicyFullName(domainName, policyName),
            version
        );

        await deletePolicyVersion(
            domainName,
            policyName,
            version
        )(fakeDispatch, getState);

        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
        expect(
            _.isEqual(fakeDispatch.getCall(1).args[0], deletePolicyAction)
        ).toBeTruthy();
    });

    it("should throw err, policy version doesn't exists in store", async () => {
        jest.spyOn(
            policiesSelectors,
            'selectPolicyVersionThunk'
        ).mockReturnValue(null);
        const fakeDispatch = sinon.spy();
        try {
            await deletePolicyVersion(
                domainName,
                policyName,
                version
            )(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e.statusCode).toBe(404);
        }
    });
    it('should throw err from server', async () => {
        jest.spyOn(
            policiesSelectors,
            'selectPolicyVersionThunk'
        ).mockReturnValue(singleStorePolicy);
        MockApi.setMockApi({
            deletePolicyVersion: jest
                .fn()
                .mockReturnValue(
                    Promise.reject({ body: { message: 'failed' } })
                ),
        });
        const fakeDispatch = sinon.spy();
        try {
            await deletePolicyVersion(
                domainName,
                policyName,
                version
            )(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e.body.message === 'failed').toBeTruthy();
        }
    });
});

describe('test setActivePolicyVersion thunk', () => {
    const domainName = 'dom';
    const policyName = 'singlePolicy';
    const version = '0';
    afterEach(() => {
        MockApi.cleanMockApi();
    });

    it('should set active policy version successfully', async () => {
        const fakeDispatch = sinon.spy();
        MockApi.setMockApi({
            setActivePolicyVersion: jest
                .fn()
                .mockReturnValue(Promise.resolve(true)),
        });
        const setActivePolicyVersionAction = setActivePolicyVersionToStore(
            getPolicyFullName(domainName, policyName),
            version
        );

        await setActivePolicyVersion(
            domainName,
            policyName,
            version
        )(fakeDispatch);

        expect(
            _.isEqual(
                fakeDispatch.getCall(0).args[0],
                setActivePolicyVersionAction
            )
        ).toBeTruthy();
    });

    it('set active policy version fail', async () => {
        MockApi.setMockApi({
            setActivePolicyVersion: jest
                .fn()
                .mockReturnValue(Promise.reject({ statusCode: 404 })),
        });
        const fakeDispatch = sinon.spy();
        try {
            await setActivePolicyVersion(
                domainName,
                policyName,
                version
            )(fakeDispatch);
            fail();
        } catch (e) {
            expect(e.statusCode).toBe(404);
        }
    });
});

describe('test deleteAssertion thunk', () => {
    const domainName = 'dom';
    const policyName = 'singlePolicy';
    const assertionId = 17409;
    const getState = () => {};

    afterEach(() => {
        jest.spyOn(policiesSelectors, 'selectPolicyThunk').mockRestore();
        MockApi.cleanMockApi();
    });

    it('delete assertion successfully', async () => {
        const fakeDispatch = sinon.spy();
        MockApi.setMockApi({
            deleteAssertion: jest.fn().mockReturnValue(Promise.resolve(true)),
        });
        jest.spyOn(policiesSelectors, 'selectPolicyThunk').mockReturnValue(
            singleStorePolicy
        );
        const deleteAssertionPolicyVersionAction =
            getDeleteAssertionPolicyVersionAction(
                getPolicyFullName(domainName, policyName),
                '0',
                assertionId
            );

        await deleteAssertion(
            domainName,
            policyName,
            assertionId
        )(fakeDispatch, getState);

        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                deleteAssertionPolicyVersionAction
            )
        ).toBeTruthy();
    });

    it("should throw err, assertion doesn't exists in store", async () => {
        const fakeDispatch = sinon.spy();
        jest.spyOn(policiesSelectors, 'selectPolicyThunk').mockReturnValue(
            null
        );
        try {
            await deleteAssertion(
                domainName,
                policyName,
                assertionId
            )(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e.statusCode).toBe(404);
        }
    });
    it('should throw err from server', async () => {
        jest.spyOn(policiesSelectors, 'selectPolicyThunk').mockReturnValue(
            singleStorePolicy
        );
        MockApi.setMockApi({
            deleteAssertion: jest
                .fn()
                .mockReturnValue(
                    Promise.reject({ body: { message: 'failed' } })
                ),
        });
        const fakeDispatch = sinon.spy();
        try {
            await deleteAssertion(
                domainName,
                policyName,
                assertionId
            )(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e.body.message).toEqual('failed');
        }
    });
});

describe('test deleteAssertionPolicyVersion thunk', () => {
    const domainName = 'dom';
    const policyName = 'singlePolicy';
    const version = '0';
    const assertionId = 17409;
    const getState = () => {};

    afterEach(() => {
        jest.spyOn(policiesSelectors, 'selectPolicyVersionThunk').mockRestore();
        MockApi.cleanMockApi();
    });

    it('should delete assertion policy version successfully', async () => {
        const fakeDispatch = sinon.spy();
        MockApi.setMockApi({
            deleteAssertionPolicyVersion: jest
                .fn()
                .mockReturnValue(Promise.resolve(true)),
        });
        jest.spyOn(
            policiesSelectors,
            'selectPolicyVersionThunk'
        ).mockReturnValue(singleStorePolicy);

        const deleteAssertionPolicyVersionAction =
            getDeleteAssertionPolicyVersionAction(
                getPolicyFullName(domainName, policyName),
                version,
                assertionId
            );

        await deleteAssertionPolicyVersion(
            domainName,
            policyName,
            version,
            assertionId
        )(fakeDispatch, getState);

        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                deleteAssertionPolicyVersionAction
            )
        ).toBeTruthy();
    });

    it(" should throw err, assertion policy version doesn't exists in store", async () => {
        const fakeDispatch = sinon.spy();
        jest.spyOn(
            policiesSelectors,
            'selectPolicyVersionThunk'
        ).mockReturnValue(null);
        try {
            await deleteAssertionPolicyVersion(
                domainName,
                policyName,
                version,
                assertionId
            )(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e.statusCode).toBe(404);
        }
    });
    it('should throw err from server', async () => {
        jest.spyOn(
            policiesSelectors,
            'selectPolicyVersionThunk'
        ).mockReturnValue(singleStorePolicy);
        MockApi.setMockApi({
            deleteAssertionPolicyVersion: jest
                .fn()
                .mockReturnValue(
                    Promise.reject({ body: { message: 'failed' } })
                ),
        });
        const fakeDispatch = sinon.spy();
        try {
            await deleteAssertionPolicyVersion(
                domainName,
                policyName,
                version,
                assertionId
            )(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e.body.message).toEqual('failed');
        }
    });
});

describe('test addAssertion thunk', () => {
    const domainName = 'dom';
    const policyName = 'singlePolicy';
    const fullPolicyName = getPolicyFullName(domainName, policyName);
    const getState = () => {};
    const { role, resource, action, effect } = apiAssertion;

    afterEach(() => {
        jest.spyOn(policiesSelectors, 'selectPolicyThunk').mockRestore();
        MockApi.cleanMockApi();
    });

    it('should add assertion successfully', async () => {
        const fakeDispatch = sinon.spy();
        MockApi.setMockApi({
            addAssertion: jest
                .fn()
                .mockReturnValue(Promise.resolve(apiAssertion)),
        });
        jest.spyOn(policiesSelectors, 'selectPolicyThunk').mockReturnValue(
            singleStorePolicy
        );

        const addAssertionPolicyVersionAction =
            getAddAssertionPolicyVersionAction(
                fullPolicyName,
                '0',
                apiAssertion
            );

        await addAssertion(
            domainName,
            policyName,
            role,
            resource,
            action,
            effect
        )(fakeDispatch, getState);

        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                addAssertionPolicyVersionAction
            )
        ).toBeTruthy();
    });
    it("should throw err, policy doesn't exists in store", async () => {
        const fakeDispatch = sinon.spy();
        jest.spyOn(policiesSelectors, 'selectPolicyThunk').mockReturnValue(
            null
        );
        try {
            await addAssertion(domainName, policyName)(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e.statusCode).toBe(404);
        }
    });
    it('should throw err from server', async () => {
        const fakeDispatch = sinon.spy();
        jest.spyOn(policiesSelectors, 'selectPolicyThunk').mockReturnValue(
            singleStorePolicy
        );
        MockApi.setMockApi({
            addAssertion: jest.fn().mockReturnValue(
                Promise.reject({
                    body: { message: 'failed' },
                })
            ),
        });
        try {
            await addAssertion(domainName, policyName)(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e.body.message).toEqual('failed');
        }
    });
});

describe('test addAssertionPolicyVersion thunk', () => {
    const domainName = 'dom';
    const policyName = 'singlePolicy';
    const version = '0';
    const fullPolicyName = getPolicyFullName(domainName, policyName);
    const getState = () => {};
    const { role, resource, action, effect } = apiAssertion;

    afterEach(() => {
        jest.spyOn(policiesSelectors, 'selectPolicyVersionThunk').mockRestore();
        MockApi.cleanMockApi();
    });

    it('should add assertion policy version successfully', async () => {
        const fakeDispatch = sinon.spy();
        MockApi.setMockApi({
            addAssertionPolicyVersion: jest
                .fn()
                .mockReturnValue(Promise.resolve(apiAssertion)),
        });
        jest.spyOn(
            policiesSelectors,
            'selectPolicyVersionThunk'
        ).mockReturnValue(singleStorePolicy);
        const addAssertionPolicyVersionAction =
            getAddAssertionPolicyVersionAction(
                fullPolicyName,
                version,
                apiAssertion
            );

        await addAssertionPolicyVersion(
            domainName,
            policyName,
            version,
            role,
            resource,
            action,
            effect
        )(fakeDispatch, getState);

        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                addAssertionPolicyVersionAction
            )
        ).toBeTruthy();
    });

    it("should throw err, policy doesn't exists in store", async () => {
        const fakeDispatch = sinon.spy();
        jest.spyOn(
            policiesSelectors,
            'selectPolicyVersionThunk'
        ).mockReturnValue(null);
        try {
            await addAssertionPolicyVersion(
                domainName,
                policyName,
                'does_not_exists'
            )(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e.statusCode).toBe(404);
        }
    });
    it('should throw err from server', async () => {
        const fakeDispatch = sinon.spy();
        jest.spyOn(
            policiesSelectors,
            'selectPolicyVersionThunk'
        ).mockReturnValue(singleStorePolicy);
        MockApi.setMockApi({
            addAssertionPolicyVersion: jest.fn().mockReturnValue(
                Promise.reject({
                    body: { message: 'failed' },
                })
            ),
        });
        try {
            await addAssertionPolicyVersion(
                domainName,
                policyName,
                version
            )(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e.body.message).toEqual('failed');
        }
    });
});

describe('test addAssertionConditions thunk', () => {
    const domainName = 'dom';
    const policyName = 'singlePolicy';
    const assertionId = 17409;
    const fullPolicyName = getPolicyFullName(domainName, policyName);
    const getState = () => {};

    afterEach(() => {
        jest.spyOn(policiesSelectors, 'selectPolicyThunk').mockRestore();
        MockApi.cleanMockApi();
    });

    it('should add assertion conditions successfully', async () => {
        const fakeDispatch = sinon.spy();
        MockApi.setMockApi({
            addAssertionConditions: jest
                .fn()
                .mockReturnValue(Promise.resolve(apiAssertionConditions)),
        });
        jest.spyOn(policiesSelectors, 'selectPolicyThunk').mockReturnValue(
            singleStorePolicy
        );
        const addAssertionConditionsAction = addAssertionConditionsToStore(
            fullPolicyName,
            '0',
            assertionId,
            apiAssertionConditions.conditionsList
        );

        await addAssertionConditions(
            domainName,
            policyName,
            assertionId
        )(fakeDispatch, getState);

        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                addAssertionConditionsAction
            )
        ).toBeTruthy();
    });

    it("should throw err - assertion doesn't exists in store", async () => {
        const fakeDispatch = sinon.spy();
        jest.spyOn(policiesSelectors, 'selectPolicyThunk').mockReturnValue(
            null
        );
        try {
            await addAssertionConditions(
                domainName,
                policyName,
                assertionId
            )(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e.statusCode).toBe(404);
        }
    });
    it('should throw err from server ', async () => {
        const fakeDispatch = sinon.spy();
        MockApi.setMockApi({
            addAssertionConditions: jest.fn().mockReturnValue(
                Promise.reject({
                    body: { message: 'failed' },
                })
            ),
        });
        jest.spyOn(policiesSelectors, 'selectPolicyThunk').mockReturnValue(
            singleStorePolicy
        );
        try {
            await addAssertionConditions(
                domainName,
                policyName,
                assertionId
            )(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e.body.message).toEqual('failed');
        }
    });
});

describe('test deleteAssertionCondition thunk', () => {
    const domainName = 'dom';
    const policyName = 'acl.ows.inbound';
    const assertionId = 34567;
    const conditionId = 1;
    const fullPolicyName = getPolicyFullName(domainName, policyName);
    const getState = () => {};

    afterEach(() => {
        jest.spyOn(policiesSelectors, 'selectPolicyThunk').mockRestore();
        MockApi.cleanMockApi();
    });

    it('should delete assertion condition successfully', async () => {
        const fakeDispatch = sinon.spy();
        jest.spyOn(policiesSelectors, 'selectPolicyThunk').mockReturnValue(
            singleStorePolicyWithAssertionConditions
        );
        MockApi.setMockApi({
            deleteAssertionCondition: jest
                .fn()
                .mockReturnValue(Promise.resolve(true)),
        });
        const deleteAssertionConditionAction =
            deleteAssertionConditionFromStore(
                fullPolicyName,
                '1',
                assertionId,
                conditionId
            );

        await deleteAssertionCondition(
            domainName,
            policyName,
            assertionId,
            conditionId
        )(fakeDispatch, getState);

        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                deleteAssertionConditionAction
            )
        ).toBeTruthy();
    });

    it("should throw err assertion condition doesn't exists in store ", async () => {
        const fakeDispatch = sinon.spy();
        jest.spyOn(policiesSelectors, 'selectPolicyThunk').mockReturnValue(
            null
        );
        try {
            await deleteAssertionCondition(
                domainName,
                policyName,
                assertionId,
                'does_not_exists'
            )(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e.statusCode).toBe(404);
        }
    });
    it('should throw err from server', async () => {
        const fakeDispatch = sinon.spy();
        jest.spyOn(policiesSelectors, 'selectPolicyThunk').mockReturnValue(
            singleStorePolicyWithAssertionConditions
        );
        MockApi.setMockApi({
            deleteAssertionCondition: jest.fn().mockReturnValue(
                Promise.reject({
                    body: { message: 'failed' },
                })
            ),
        });
        try {
            await deleteAssertionCondition(
                domainName,
                policyName,
                assertionId,
                conditionId
            )(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e.body.message).toEqual('failed');
        }
    });
});

describe('test deleteAssertionConditions thunk', () => {
    const domainName = 'dom';
    const policyName = 'acl.ows.inbound';
    const assertionId = 34567;
    const fullPolicyName = getPolicyFullName(domainName, policyName);
    const getState = () => {};

    afterEach(() => {
        jest.spyOn(policiesSelectors, 'selectPolicyThunk').mockRestore();
        MockApi.cleanMockApi();
    });

    it('should delete assertion conditions successfully', async () => {
        const fakeDispatch = sinon.spy();
        jest.spyOn(policiesSelectors, 'selectPolicyThunk').mockReturnValue(
            singleStorePolicyWithAssertionConditions
        );
        MockApi.setMockApi({
            deleteAssertionConditions: jest
                .fn()
                .mockReturnValue(Promise.resolve(true)),
        });
        const deleteAssertionConditionsAction =
            deleteAssertionConditionsFromStore(
                fullPolicyName,
                '1',
                assertionId
            );

        await deleteAssertionConditions(
            domainName,
            policyName,
            assertionId
        )(fakeDispatch, getState);

        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
        expect(
            _.isEqual(
                fakeDispatch.getCall(1).args[0],
                deleteAssertionConditionsAction
            )
        ).toBeTruthy();
    });
    it(" should throw err - assertion conditions doesn't exists in store", async () => {
        const fakeDispatch = sinon.spy();
        jest.spyOn(policiesSelectors, 'selectPolicyThunk').mockReturnValue(
            null
        );
        try {
            await deleteAssertionConditions(
                domainName,
                policyName,
                98765
            )(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e.statusCode).toBe(404);
        }
    });
    it('should throw err from server', async () => {
        const fakeDispatch = sinon.spy();
        jest.spyOn(policiesSelectors, 'selectPolicyThunk').mockReturnValue(
            singleStorePolicyWithAssertionConditions
        );
        MockApi.setMockApi({
            deleteAssertionConditions: jest.fn().mockReturnValue(
                Promise.reject({
                    body: { message: 'failed' },
                })
            ),
        });
        try {
            await deleteAssertionConditions(
                domainName,
                policyName,
                assertionId
            )(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e.body.message).toEqual('failed');
        }
    });
});

// TODO - after we change the function according to back-end changes
// describe( 'test addPolicy thunk', () => {
//     it('add policy', async () => {
//         const policies = require('../../../redux/thunks/policies');
//         jest.spyOn(utils,'getPolicies').mockReturnValue(true);
//         const getState = () => {return {policies: {}}};
//     });
//     it('policy already exists, should throw err', () => {
//
//     })
// });
