export const LOADING_IN_PROCESS = 'LOADING_IN_PROCESS';
export const loadingInProcess = (func) => ({
    type: LOADING_IN_PROCESS,
    payload: { funcName: func },
});

export const LOADING_SUCCESS = 'LOADING_SUCCESS';
export const loadingSuccess = (func) => ({
    type: LOADING_SUCCESS,
    payload: { funcName: func },
});

export const LOADING_FAILED = 'LOADING_FAILED';
export const loadingFailed = (func) => ({
    type: LOADING_FAILED,
    payload: { funcName: func },
});
