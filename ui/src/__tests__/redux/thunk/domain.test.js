import { getDomainData, updateBusinessService } from '../../../redux/thunks/domain';
import { domainName, expiry, storeDomainData } from '../../config/config.test';
import {
    getLoadDomainDataAction,
    getStoreDomainDataAction,
} from '../../../tests_utils/thunkUtils';
import MockApi from '../../../mock/MockApi';
import sinon from 'sinon';
import { _ } from 'lodash';
import { getExpiryTime } from '../../../redux/utils';
import { returnDomainData, updateBusinessServiceInStore } from '../../../redux/actions/domain-data';
import { loadingInProcess, loadingSuccess } from '../../../redux/actions/loading';

const utils = require('../../../redux/utils');

describe( 'test getDomainData thunk', () => {

    const userName = 'user';
    const domainDetails = {
        enabled: true,
        auditEnabled: false,
        ypmId: 0,
        memberExpiryDays: 76,
        tags: {
            tag1: { list: ['tagValue1', 'tagValue2'] },
            tag2: { list: ['tagValue3'] },
        },
        name: 'dom',
        modified: '2022-07-25T13:43:05.183Z',
        id: '62bb4f70-f7a5-11ec-8202-e7ae4e1596ac',
    }

    beforeAll(() => {
        jest.spyOn(utils,'getExpiryTime').mockReturnValue(expiry);
        MockApi.setMockApi({
            getDomain: jest.fn().mockReturnValue(
                Promise.resolve(domainDetails)
            ),
            isAWSTemplateApplied: jest.fn().mockReturnValue(
                Promise.resolve(storeDomainData.isAWSTemplateApplied)
            ),
            getHeaderDetails: jest.fn().mockReturnValue(
                Promise.resolve(storeDomainData.headerDetails)
            ),
            getPendingDomainMembersListByDomain: jest.fn().mockReturnValue(
                Promise.resolve(storeDomainData.pendingMembersList)
            ),
            getFeatureFlag: jest.fn().mockReturnValue(
                Promise.resolve(storeDomainData.featureFlag)
            ),
            getMeta: jest.fn().mockReturnValue(
                Promise.resolve(storeDomainData.businessServices)
            ),
            getAuthorityAttributes: jest.fn().mockReturnValue(
                Promise.resolve(storeDomainData.authorityAttributes)
            ),
        })
    });

    afterAll(() => {
        MockApi.cleanMockApi();
        jest.spyOn(utils,'getExpiryTime').mockRestore();

    })

    afterEach( () => {
        jest.spyOn(utils,'isExpired').mockRestore();
    });


    it('test getDomainData new domain without current domain scenario', async () => {
        const getState = () => { return {domainData: {}}}
        const fakeDispatch = sinon.spy();
        await getDomainData('newDomain', userName)(fakeDispatch, getState);

        expect(_.isEqual(fakeDispatch.getCall(0).args[0], loadingInProcess('getDomainData'))).toBeTruthy();
        expect(_.isEqual(fakeDispatch.getCall(1).args[0], getLoadDomainDataAction('newDomain', storeDomainData))).toBeTruthy();
        expect(_.isEqual(fakeDispatch.getCall(2).args[0], loadingSuccess('getDomainData'))).toBeTruthy();
    })

    it('test getDomainData new domain with current domain scenario', async () => {
        const domainData =  {domainName, expiry: getExpiryTime(), storeDomainData};
        const getState = () => { return {domainData, domains: {}}};
        const fakeDispatch = sinon.spy();
        await getDomainData('newDomain', userName)(fakeDispatch, getState);

        expect(_.isEqual(fakeDispatch.getCall(0).args[0], getStoreDomainDataAction(domainData))).toBeTruthy();
        expect(_.isEqual(fakeDispatch.getCall(1).args[0], loadingInProcess('getDomainData'))).toBeTruthy();
        expect(_.isEqual(fakeDispatch.getCall(2).args[0], getLoadDomainDataAction('newDomain', storeDomainData))).toBeTruthy();
        expect(_.isEqual(fakeDispatch.getCall(3).args[0], loadingSuccess('getDomainData'))).toBeTruthy();
    })

    it('test getDomainData current domain scenario', async () => {
        jest.spyOn(utils,'isExpired').mockReturnValue(false);
        const getState = () => { return {domainData: {domainName, expiry: getExpiryTime()}}};
        const fakeDispatch = sinon.spy();
        const returnDomainDataAction = returnDomainData();
        await getDomainData(domainName, userName)(fakeDispatch, getState);
        expect(_.isEqual(fakeDispatch.getCall(0).args[0], returnDomainDataAction)).toBeTruthy();
    })

    it('test getDomainData current domain expired scenario', async () => {
        jest.spyOn(utils,'isExpired').mockReturnValue(true);
        const getState = () => { return {domainData: {domainName, expiry: getExpiryTime()}}};
        const fakeDispatch = sinon.spy();
        await getDomainData(domainName, userName)(fakeDispatch, getState);

        expect(_.isEqual(fakeDispatch.getCall(0).args[0], loadingInProcess('getDomainData'))).toBeTruthy();
        expect(_.isEqual(fakeDispatch.getCall(1).args[0], getLoadDomainDataAction(domainName, storeDomainData))).toBeTruthy();
        expect(_.isEqual(fakeDispatch.getCall(2).args[0], loadingSuccess('getDomainData'))).toBeTruthy();
    })

    it('test getDomainData new domain already in the store scenario', async () => {
        jest.spyOn(utils,'isExpired').mockReturnValue(false);
        const domainData =  {domainName, expiry: getExpiryTime(), domainData:{}};
        const newDomain = 'newDomain';
        const catchDomainData =  {domainData: storeDomainData, 'domainName': newDomain, expiry: getExpiryTime()};
        const getState = () => { return {domainData, domains: {newDomain: {domainData: catchDomainData}}}};
        const fakeDispatch = sinon.spy();
        await getDomainData('newDomain')(fakeDispatch, getState);

        expect(_.isEqual(fakeDispatch.getCall(0).args[0], getStoreDomainDataAction(domainData))).toBeTruthy();
        expect(_.isEqual(fakeDispatch.getCall(1).args[0], getLoadDomainDataAction(newDomain, storeDomainData))).toBeTruthy();
    })
});

describe( 'test updateBusinessService thunk', () => {

    const meta = {
        businessService: 'businessService'
    }

    afterEach(() => {
        MockApi.cleanMockApi();
    });

    it('update business service successfully', async () => {
        MockApi.setMockApi({
            putMeta: jest.fn().mockReturnValue(Promise.resolve(true))
        });
        const fakeDispatch = sinon.spy();
        const updateBusinessServiceAction = updateBusinessServiceInStore(meta.businessService);

        await updateBusinessService(domainName, meta)(fakeDispatch);
        expect(_.isEqual(fakeDispatch.getCall(0).args[0], updateBusinessServiceAction)).toBeTruthy();
    });

});
