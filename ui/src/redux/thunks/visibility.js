import {
    loadServiceDependencies,
    returnServiceDependencies,
} from '../actions/visibility';
import { storeServiceDependencies } from '../actions/domains';
import { getServiceDependenciesApiCall } from './utils/visibility';
import { isExpired } from '../utils';

export const getServiceDependencies =
    (domainName) => async (dispatch, getState) => {
        if (getState().serviceDependencies.expiry) {
            if (getState().serviceDependencies.domainName !== domainName) {
                dispatch(
                    storeServiceDependencies(getState().serviceDependencies)
                );
                if (
                    getState().domains[domainName] &&
                    getState().domains[domainName].serviceDependencies &&
                    !isExpired(
                        getState().domains[domainName].serviceDependencies
                            .expiry
                    )
                ) {
                    dispatch(
                        loadServiceDependencies(
                            getState().domains[domainName].serviceDependencies
                                .serviceDependencies,
                            domainName,
                            getState().domains[domainName].serviceDependencies
                                .expiry
                        )
                    );
                } else {
                    await getServiceDependenciesApiCall(domainName, dispatch);
                }
            } else if (isExpired(getState().serviceDependencies.expiry)) {
                await getServiceDependenciesApiCall(domainName, dispatch);
            } else {
                dispatch(returnServiceDependencies());
            }
        } else {
            await getServiceDependenciesApiCall(domainName, dispatch);
        }
    };
