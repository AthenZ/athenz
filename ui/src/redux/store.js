import { applyMiddleware, combineReducers, createStore } from 'redux';
import { isLoading } from './reducers';
import { groups } from './reducers/groups';
import { roles } from './reducers/roles';
import { user } from './reducers/user';
import { domainData } from './reducers/domain-data';
import { domains } from './reducers/domains';
import thunk from 'redux-thunk';
import { composeWithDevTools } from 'redux-devtools-extension';
import { services } from './reducers/services';
import { policies } from './reducers/policies';
import { templates } from './reducers/templates';
import { serviceDependencies } from './reducers/visibility';
import { microsegmentation } from './reducers/microsegmentation';
import { createWrapper, HYDRATE } from 'next-redux-wrapper';

const combinedReducer = combineReducers({
    services,
    domains,
    domainData,
    roles,
    groups,
    policies,
    templates,
    serviceDependencies,
    microsegmentation,
    isLoading,
    user,
});

const reducer = (state, action) => {
    return combinedReducer(state, action);
};

export const initStore = (initialState) =>
    createStore(
        reducer,
        initialState,
        composeWithDevTools(applyMiddleware(thunk))
    );

export const wrapper = createWrapper(initStore);
