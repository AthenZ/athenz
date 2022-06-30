import { applyMiddleware, combineReducers, createStore } from 'redux';
import { isLoading } from './reducers';
import { groups } from './reducers/groups';
import { roles } from './reducers/roles';
import { domainData } from './reducers/domain-data';
import { domains } from './reducers/domains';
import thunk from 'redux-thunk';
import { composeWithDevTools } from 'redux-devtools-extension';
import { services } from './reducers/services';
import { policies } from './reducers/policies';
import { templates } from './reducers/templates';
import { domainHistory } from './reducers/history';
import { serviceDependencies } from './reducers/visibility';

const reducer = {
    services,
    domains,
    domainData,
    roles,
    groups,
    policies,
    templates,
    domainHistory,
    serviceDependencies,
    isLoading,
};

const rootReducer = combineReducers(reducer);

export const configureStore = () =>
    createStore(rootReducer, composeWithDevTools(applyMiddleware(thunk)));
