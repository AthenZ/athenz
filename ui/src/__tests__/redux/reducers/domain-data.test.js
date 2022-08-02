import { _ } from 'lodash';
import { storeDomainData, domainName, expiry } from '../../config/config.test';
import AppUtils from '../../../components/utils/AppUtils';
import { LOAD_DOMAIN_DATA } from '../../../redux/actions/domain-data';
import { domainData } from '../../../redux/reducers/domain-data';
import {
    UPDATE_SETTING_TO_STORE,
    UPDATE_TAGS_TO_STORE,
} from '../../../redux/actions/collections';

describe('DomainData Reducer', () => {
    it('should load the domainData', () => {
        const initialState = {};
        const action = {
            type: LOAD_DOMAIN_DATA,
            payload: {
                domainData: storeDomainData,
                domainName: domainName,
                expiry: expiry,
            },
        };
        const expectedState = {
            domainData: storeDomainData,
            domainName: domainName,
            expiry: expiry,
        };
        const newState = domainData(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should update setting', () => {
        let newSettings = {
            groupExpiryDays: '50',
            memberExpiryDays: '100',
            roleCertExpiryMins: '',
            serviceExpiryDays: '',
            tokenExpiryMins: '20',
        };
        const initialState = {
            domainData: storeDomainData,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: UPDATE_SETTING_TO_STORE,
            payload: {
                collectionSettings: newSettings,
                category: 'domain',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.domainData.groupExpiryDays = '50';
        expectedState.domainData.memberExpiryDays = '100';
        expectedState.domainData.tokenExpiryMins = '20';
        expectedState.domainData.serviceExpiryDays = '';
        expectedState.domainData.roleCertExpiryMins = '';
        const newState = domainData(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should add tags', () => {
        let newTags = {
            tag1: { list: ['tagValue1', 'tagValue2'] },
            tag2: { list: ['tagValue3'] },
            newtag: { list: ['newtagvalue1', 'newtagvalue2'] },
        };
        const initialState = {
            domainData: storeDomainData,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: UPDATE_TAGS_TO_STORE,
            payload: {
                collectionTags: newTags,
                category: 'domain',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.domainData.tags = newTags;
        const newState = domainData(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should delete tag', () => {
        let newTags = {
            tag1: { list: ['tagValue1', 'tagValue2'] },
        };
        const initialState = {
            domainData: storeDomainData,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: UPDATE_TAGS_TO_STORE,
            payload: {
                collectionTags: newTags,
                category: 'domain',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        delete expectedState.domainData.tags.tag2;
        const newState = domainData(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should edit tag', () => {
        let newTags = {
            tag1: { list: ['newtagValue1', 'tagValue2'] },
            tag2: { list: ['tagValue3', 'addtagValue4'] },
        };
        const initialState = {
            domainData: storeDomainData,
            domainName: domainName,
            expiry: expiry,
        };
        const action = {
            type: UPDATE_TAGS_TO_STORE,
            payload: {
                collectionTags: newTags,
                category: 'domain',
            },
        };
        const expectedState = AppUtils.deepClone(initialState);
        expectedState.domainData.tags.tag2.list.push('addtagValue4');
        expectedState.domainData.tags.tag1.list[0] = 'newtagValue1';
        const newState = domainData(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
});
