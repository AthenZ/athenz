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
import { getExpiryTime, listToMap } from '../../../redux/utils';
import {
    addAssertion,
    addAssertionConditions,
    addAssertionPolicyVersion,
    addPolicy,
    deleteAssertion,
    deleteAssertionCondition,
    deleteAssertionConditions,
    deleteAssertionPolicyVersion,
    deletePolicy,
    deletePolicyVersion,
    duplicatePolicyVersion,
    getAssertionId,
    getPolicies,
    getPolicy,
    getPolicyVersion,
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
    addPolicyToStore,
    deleteAssertionConditionFromStore,
    deleteAssertionConditionsFromStore,
    deletePolicyFromStore,
    deletePolicyVersionFromStore,
    returnPolicies,
    setActivePolicyVersionToStore,
} from '../../../redux/actions/policies';
import {
    apiAssertion,
    configStorePolicies,
    singleApiPolicy,
    singleStorePolicy,
    singleStorePolicyWithAssertionConditions,
} from '../config/policy.test';
import { apiAssertionConditions } from '../../config/config.test';
import { getPolicyFullName } from '../../../redux/thunks/utils/policies';
import {
    loadingFailed,
    loadingInProcess,
    loadingSuccess,
} from '../../../redux/actions/loading';
import AppUtils from '../../../components/utils/AppUtils';
import { roleDelimiter, serviceDelimiter } from '../../../redux/config';

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

    it('test getPolicies should fail to get from the server', async () => {
        const getState = () => {
            return { policies: {} };
        };
        const err = { statusCode: 400, body: { massage: 'failed' } };
        MockApi.setMockApi({
            getPolicies: jest.fn().mockReturnValue(Promise.reject(err)),
        });
        const fakeDispatch = sinon.spy();
        try {
            await getPolicies('newDomain')(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(_.isEqual(e, err)).toBeTruthy();
            expect(
                _.isEqual(
                    fakeDispatch.getCall(0).args[0],
                    loadingInProcess('getPolicies')
                )
            ).toBeTruthy();
            expect(
                _.isEqual(
                    fakeDispatch.getCall(1).args[0],
                    loadingFailed('getPolicies', err)
                )
            ).toBeTruthy();
        }
    });
});

describe('test getPolicy thunk', () => {
    const domainName = 'dom';
    const policyName = 'singlepolicy';
    const getState = () => {};

    afterEach(() => {
        jest.spyOn(policiesSelectors, 'selectPolicy').mockRestore();
        MockApi.cleanMockApi();
    });

    it('should get policy successfully', async () => {
        const fakeDispatch = sinon.spy();
        MockApi.setMockApi({
            getPolicy: jest
                .fn()
                .mockReturnValue(Promise.resolve(singleApiPolicy)),
        });
        jest.spyOn(policiesSelectors, 'selectPolicy').mockReturnValue(null);
        const addPolicyToStoreAction = addPolicyToStore({
            ...singleApiPolicy,
            assertions: listToMap(singleApiPolicy.assertions, 'id'),
        });

        await getPolicy(domainName, policyName)(fakeDispatch, getState);

        expect(fakeDispatch.callCount).toBe(2);
        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
        expect(
            _.isEqual(fakeDispatch.getCall(1).args[0], addPolicyToStoreAction)
        ).toBeTruthy();
    });

    it('should return policy from store', async () => {
        jest.spyOn(policiesSelectors, 'selectPolicy').mockReturnValue(
            singleApiPolicy
        );
        const fakeDispatch = sinon.spy();
        let policy = await getPolicy(domainName, policyName)(
            fakeDispatch,
            getState
        );
        expect(fakeDispatch.callCount).toBe(1);
        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
        expect(_.isEqual(policy, singleApiPolicy));
    });

    it('should throw err from server', async () => {
        jest.spyOn(policiesSelectors, 'selectPolicy').mockReturnValue(null);
        MockApi.setMockApi({
            getPolicy: jest
                .fn()
                .mockReturnValue(
                    Promise.reject({ body: { message: 'failed' } })
                ),
        });
        const fakeDispatch = sinon.spy();
        try {
            await getPolicy(domainName, policyName)(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e.body.message === 'failed').toBeTruthy();
        }
    });
});

describe('test getPolicyVersion thunk', () => {
    const domainName = 'dom';
    const policyName = 'singlepolicy';
    const getState = () => {};

    afterEach(() => {
        jest.spyOn(policiesSelectors, 'selectPolicyVersion').mockRestore();
        MockApi.cleanMockApi();
    });

    it('should get policyVersion successfully', async () => {
        const fakeDispatch = sinon.spy();
        MockApi.setMockApi({
            getPolicyVersion: jest
                .fn()
                .mockReturnValue(Promise.resolve(singleApiPolicy)),
        });
        jest.spyOn(policiesSelectors, 'selectPolicyVersion').mockReturnValue(
            null
        );
        const addPolicyToStoreAction = addPolicyToStore({
            ...singleApiPolicy,
            assertions: listToMap(singleApiPolicy.assertions, 'id'),
        });

        await getPolicyVersion(
            domainName,
            policyName,
            '0'
        )(fakeDispatch, getState);

        expect(fakeDispatch.callCount).toBe(2);
        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
        expect(
            _.isEqual(fakeDispatch.getCall(1).args[0], addPolicyToStoreAction)
        ).toBeTruthy();
    });

    it('should return policyVersion from store', async () => {
        jest.spyOn(policiesSelectors, 'selectPolicyVersion').mockReturnValue(
            singleApiPolicy
        );
        const fakeDispatch = sinon.spy();
        let policyVersion = await getPolicyVersion(
            domainName,
            policyName,
            '0'
        )(fakeDispatch, getState);
        expect(fakeDispatch.callCount).toBe(1);
        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
        expect(_.isEqual(policyVersion, singleApiPolicy));
    });

    it('should throw err from server', async () => {
        jest.spyOn(policiesSelectors, 'selectPolicyVersion').mockReturnValue(
            null
        );
        MockApi.setMockApi({
            getPolicyVersion: jest
                .fn()
                .mockReturnValue(
                    Promise.reject({ body: { message: 'failed' } })
                ),
        });
        const fakeDispatch = sinon.spy();
        try {
            await getPolicyVersion(domainName, policyName)(
                fakeDispatch,
                getState
            );
            fail();
        } catch (e) {
            expect(e.body.message === 'failed').toBeTruthy();
        }
    });
});

describe('test deletePolicy thunk', () => {
    const domainName = 'dom';
    const policyName = 'singlepolicy';
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
            AppUtils.deepClone(singleStorePolicy)
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
            AppUtils.deepClone(singleStorePolicy)
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
    const policyName = 'singlepolicy';
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
        ).mockReturnValue(AppUtils.deepClone(singleStorePolicy));
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
        ).mockReturnValue(AppUtils.deepClone(singleStorePolicy));
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
    const policyName = 'singlepolicy';
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
    const policyName = 'singlepolicy';
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
            AppUtils.deepClone(singleStorePolicy)
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
            AppUtils.deepClone(singleStorePolicy)
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
    const policyName = 'singlepolicy';
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
        ).mockReturnValue(AppUtils.deepClone(singleStorePolicy));

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
        ).mockReturnValue(AppUtils.deepClone(singleStorePolicy));
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
    const policyName = 'singlepolicy';
    const fullPolicyName = getPolicyFullName(domainName, policyName);
    const getState = () => {};
    const { role, resource, action, effect } = AppUtils.deepClone(apiAssertion);

    afterEach(() => {
        jest.spyOn(policiesSelectors, 'selectPolicyThunk').mockRestore();
        MockApi.cleanMockApi();
    });

    it('should add assertion successfully', async () => {
        const fakeDispatch = sinon.spy();
        MockApi.setMockApi({
            addAssertion: jest
                .fn()
                .mockReturnValue(
                    Promise.resolve(AppUtils.deepClone(apiAssertion))
                ),
        });
        jest.spyOn(policiesSelectors, 'selectPolicyThunk').mockReturnValue(
            AppUtils.deepClone(singleStorePolicy)
        );

        const addAssertionPolicyVersionAction =
            getAddAssertionPolicyVersionAction(
                fullPolicyName,
                '0',
                AppUtils.deepClone(apiAssertion)
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
        expect(fakeDispatch.getCall(1).args[0]).toEqual(
            addAssertionPolicyVersionAction
        );
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
            AppUtils.deepClone(singleStorePolicy)
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
    const policyName = 'singlepolicy';
    const version = '0';
    const fullPolicyName = getPolicyFullName(
        domainName,
        policyName.toLowerCase()
    );
    const getState = () => {};
    const { role, resource, action, effect } = AppUtils.deepClone(apiAssertion);

    afterEach(() => {
        jest.spyOn(policiesSelectors, 'selectPolicyVersionThunk').mockRestore();
        MockApi.cleanMockApi();
    });
    it('should add assertion policy version successfully', async () => {
        const fakeDispatch = sinon.spy();
        MockApi.setMockApi({
            addAssertionPolicyVersion: jest
                .fn()
                .mockReturnValue(
                    Promise.resolve(AppUtils.deepClone(apiAssertion))
                ),
        });
        jest.spyOn(
            policiesSelectors,
            'selectPolicyVersionThunk'
        ).mockReturnValue(AppUtils.deepClone(singleStorePolicy));
        const addAssertionPolicyVersionAction =
            getAddAssertionPolicyVersionAction(
                fullPolicyName,
                version,
                AppUtils.deepClone(apiAssertion)
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
        expect(fakeDispatch.getCall(1).args[0]).toEqual(
            addAssertionPolicyVersionAction
        );
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
        ).mockReturnValue(AppUtils.deepClone(singleStorePolicy));
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
    const policyName = 'singlepolicy';
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
            AppUtils.deepClone(singleStorePolicy)
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
        expect(fakeDispatch.getCall(1).args[0]).toEqual(
            addAssertionConditionsAction
        );
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
            AppUtils.deepClone(singleStorePolicy)
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
            AppUtils.deepClone(singleStorePolicyWithAssertionConditions)
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
            AppUtils.deepClone(singleStorePolicyWithAssertionConditions)
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
            AppUtils.deepClone(singleStorePolicyWithAssertionConditions)
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
            AppUtils.deepClone(singleStorePolicyWithAssertionConditions)
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

describe('test addPolicy thunk', () => {
    const domainName = 'dom';
    const policyName = 'singlepolicy';
    const getState = () => {};

    afterEach(() => {
        jest.spyOn(policiesSelectors, 'selectPolicyThunk').mockRestore();
        MockApi.cleanMockApi();
    });

    it('should add policy successfully', async () => {
        const fakeDispatch = sinon.spy();
        MockApi.setMockApi({
            addPolicy: jest
                .fn()
                .mockReturnValue(
                    Promise.resolve(AppUtils.deepClone(singleApiPolicy))
                ),
        });
        jest.spyOn(policiesSelectors, 'selectPoliciesThunk').mockReturnValue(
            AppUtils.deepClone(configStorePolicies)
        );

        await addPolicy(domainName, policyName)(fakeDispatch, getState);
        expect(fakeDispatch.getCall(0).args[0]).toBeTruthy();
        expect(fakeDispatch.getCall(1).args[0]).toEqual(
            addPolicyToStore({
                ...singleStorePolicy,
                assertions: singleStorePolicy.assertions,
            })
        );
    });

    it('should throw err, policy already exists in store', async () => {
        jest.spyOn(policiesSelectors, 'selectPoliciesThunk').mockReturnValue(
            AppUtils.deepClone(configStorePolicies)
        );
        const fakeDispatch = sinon.spy();
        try {
            await addPolicy(domainName, 'admin')(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e.statusCode).toBe(500);
            expect(e.body.message).toBe('Policy admin exists in domain dom');
        }
    });

    it('should throw err from server', async () => {
        jest.spyOn(policiesSelectors, 'selectPoliciesThunk').mockReturnValue(
            AppUtils.deepClone(configStorePolicies)
        );
        MockApi.setMockApi({
            addPolicy: jest
                .fn()
                .mockReturnValue(
                    Promise.reject({ body: { message: 'failed' } })
                ),
        });
        const fakeDispatch = sinon.spy();
        try {
            await addPolicy(domainName, policyName)(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e.body.message === 'failed').toBeTruthy();
        }
    });
});

describe('test duplicatePolicyVersion thunk', () => {
    const domainName = 'dom';
    const policyName = 'singlepolicy';
    const getState = () => {};

    afterEach(() => {
        MockApi.cleanMockApi();
    });

    it('should duplicate policy version successfully', async () => {
        const fakeDispatch = sinon.spy();
        let duplicatePolicy = AppUtils.deepClone(singleApiPolicy);
        duplicatePolicy.assertions[0].id += 1;
        duplicatePolicy.version = '1';
        MockApi.setMockApi({
            duplicatePolicyVersion: jest
                .fn()
                .mockReturnValue(Promise.resolve(duplicatePolicy)),
        });
        jest.spyOn(policiesSelectors, 'selectPoliciesThunk').mockReturnValue(
            AppUtils.deepClone(configStorePolicies)
        );

        await duplicatePolicyVersion(
            domainName,
            policyName,
            '0',
            '1'
        )(fakeDispatch, getState);
        expect(fakeDispatch.getCall(0).args[0]).toEqual(
            addPolicyToStore({
                ...duplicatePolicy,
                assertions: listToMap(duplicatePolicy.assertions, 'id'),
            })
        );
    });

    it('should throw err from server', async () => {
        MockApi.setMockApi({
            duplicatePolicyVersion: jest
                .fn()
                .mockReturnValue(
                    Promise.reject({ body: { message: 'failed' } })
                ),
        });
        const fakeDispatch = sinon.spy();
        try {
            await duplicatePolicyVersion(
                domainName,
                policyName,
                '0',
                '1'
            )(fakeDispatch, getState);
            fail();
        } catch (e) {
            expect(e.body.message === 'failed').toBeTruthy();
        }
    });
});

describe('test getAssertionId thunk', () => {
    const domainName = 'dom';
    const policyName = 'singlepolicy';
    const getState = () => {};

    it('should get assertionId successfully', async () => {
        const fakeDispatch = sinon.spy();
        jest.spyOn(policiesSelectors, 'selectPolicy').mockReturnValue(
            AppUtils.deepClone(singleApiPolicy)
        );
        const { role, resource, action, effect } =
            singleApiPolicy.assertions[0];
        const assertionId = await getAssertionId(
            domainName,
            policyName,
            role.split(':role.')[1],
            resource.split(':')[1],
            action,
            effect
        )(fakeDispatch, getState);
        expect(assertionId).toBe(singleApiPolicy.assertions[0].id);
    });

    it('should throw err, policy does not exist in the store', async () => {
        const fakeDispatch = sinon.spy();
        jest.spyOn(policiesSelectors, 'selectPolicy').mockReturnValue(null);
        const { role, resource, action, effect } =
            singleApiPolicy.assertions[0];
        try {
            await getAssertionId(
                domainName,
                policyName,
                role.split(':role.')[1],
                resource.split(':')[1],
                action,
                effect
            )(fakeDispatch, getState);
        } catch (e) {
            expect(e.statusCode).toBe(404);
        }
    });

    it('should not found assertionId', async () => {
        const fakeDispatch = sinon.spy();
        jest.spyOn(policiesSelectors, 'selectPolicy').mockReturnValue(
            AppUtils.deepClone(singleApiPolicy)
        );
        const { role, resource, effect } = singleApiPolicy.assertions[0];
        try {
            await getAssertionId(
                domainName,
                policyName,
                role.split(':role.')[1],
                resource.split(':')[1],
                'f' + 'different_action',
                effect
            )(fakeDispatch, getState);
        } catch (e) {
            expect(e.statusCode).toBe(404);
        }
    });
});
