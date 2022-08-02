import { _ } from 'lodash';
import {
    LOADING_FAILED,
    LOADING_IN_PROCESS,
    LOADING_SUCCESS,
} from '../../../redux/actions/loading';
import { loading } from '../../../redux/reducers/loading';

describe('Loading Reducer', () => {
    it('should load the func name in', () => {
        const initialState = [];
        const action = {
            type: LOADING_IN_PROCESS,
            payload: {
                funcName: 'getPolicies',
            },
        };
        const expectedState = ['getPolicies'];
        const newState = loading(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should remove func from state due success', () => {
        const initialState = ['getPolicies', 'getRoles'];
        const action = {
            type: LOADING_SUCCESS,
            payload: {
                funcName: 'getRoles',
            },
        };
        const expectedState = ['getPolicies'];
        const newState = loading(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
    it('should remove func from state due failed', () => {
        const initialState = ['getPolicies', 'getRoles'];
        const action = {
            type: LOADING_FAILED,
            payload: {
                funcName: 'getRoles',
            },
        };
        const expectedState = ['getPolicies'];
        const newState = loading(initialState, action);
        expect(_.isEqual(newState, expectedState)).toBeTruthy();
    });
});
