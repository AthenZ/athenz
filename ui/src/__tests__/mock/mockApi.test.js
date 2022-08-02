import API from '../../api';
import MockApi from '../../mock/MockApi';

describe('test mockApi class', () => {
    let originalApi;
    beforeAll(() => {
        originalApi = API();
    });
    afterEach(() => {
        MockApi.cleanMockApi();
    });
    it('should be mock api', () => {
        const mockApi = {
            getPolicies: jest.fn(),
        };
        MockApi.setMockApi(mockApi);
        expect(API()).toEqual(mockApi);
    });
    it('should be original api', () => {
        const mockApi = {
            getPolicies: jest.fn(),
        };
        MockApi.setMockApi(mockApi);
        MockApi.cleanMockApi();
        expect(JSON.stringify(API())).toEqual(JSON.stringify(originalApi));
    });
});
