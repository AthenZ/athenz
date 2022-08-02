const origApi = require('../api').default;

export default class MockApi {
    static setMockApi(mockApi) {
        require('../api').default = () => {
            return mockApi;
        };
    }
    static cleanMockApi() {
        require('../api').default = () => {
            return origApi();
        };
    }
}
