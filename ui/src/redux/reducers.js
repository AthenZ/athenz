import {
    LOADING_FAILED,
    LOADING_IN_PROCESS,
    LOADING_SUCCESS,
} from './actions/loading.js';

export const isLoading = (state = [], action) => {
    const { type, payload } = action;
    switch (type) {
        case LOADING_IN_PROCESS: {
            const { funcName } = payload;
            // console.log((LOADING_IN_PROCESS, funcName));
            return [...state, funcName];
        }
        case LOADING_SUCCESS: {
            const { funcName } = payload;
            // console.log((LOADING_SUCCESS, funcName));
            return state.filter((func) => func !== funcName);
        }
        case LOADING_FAILED:
            const { funcName } = payload;
            return state.filter((func) => func !== funcName);
        default:
            return state;
    }
};
