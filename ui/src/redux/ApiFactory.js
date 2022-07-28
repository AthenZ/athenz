import API from '../api';

export default class ApiFactory {
    static mockApi = null;
    static setMockApi(mockApi) {
        ApiFactory.mockApi = mockApi;
    }
    static API() {
        return ApiFactory.mockApi ? ApiFactory.mockApi : API();
    }
    static setDefaultApi() {
        ApiFactory.mockApi = null;
    }
}
