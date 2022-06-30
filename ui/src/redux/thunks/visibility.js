import API from '../../api';
import { loadingInProcess, loadingSuccess } from '../actions/loading';
import {
    loadServiceDependencies,
    returnServiceDependencies,
} from '../actions/visibility';
import { storeServiceDependencies } from '../actions/domains';
import { getExpiryTime } from '../utils';

const api = API();

export const getServiceDependencies =
    (domainName) => async (dispatch, getState) => {
        if (getState().serviceDependencies.expiry) {
            if (getState().serviceDependencies.domainName !== domainName) {
                dispatch(loadingInProcess('getServiceDependencies'));
                dispatch(
                    storeServiceDependencies(getState().serviceDependencies)
                );
                if (
                    getState().domains[domainName] &&
                    getState().domains[domainName].serviceDependencies &&
                    getState().domains[domainName].serviceDependencies.expiry >
                        0
                ) {
                    dispatch(
                        loadServiceDependencies(
                            getState().domains[domainName].serviceDependencies,
                            domainName,
                            getState().domains[domainName].serviceDependencies
                                .expiry
                        )
                    );
                } else {
                    const serviceDependencies =
                        await api.getServiceDependencies(domainName);
                    dispatch(loadServiceDependencies(serviceDependencies));
                    dispatch(loadingSuccess('getServiceDependencies'));
                }
            } else if (getState().serviceDependencies.expiry <= 0) {
                dispatch(loadingInProcess('getServiceDependencies'));
                const serviceDependencies = await api.getServiceDependencies(
                    domainName
                );
                const expiry = getExpiryTime();
                dispatch(
                    loadServiceDependencies(
                        serviceDependencies,
                        domainName,
                        expiry
                    )
                );
                dispatch(loadingSuccess('getServiceDependencies'));
            } else {
                dispatch(returnServiceDependencies());
            }
        } else {
            dispatch(loadingInProcess('getServiceDependencies'));
            console.log(
                'about to loadServiceDependencies for domain:',
                domainName
            );
            const serviceDependencies = await api.getServiceDependencies(
                domainName
            );
            console.log('loadServiceDependencies success', serviceDependencies);
            const expiry = getExpiryTime();
            dispatch(
                loadServiceDependencies(serviceDependencies, domainName, expiry)
            );
            dispatch(loadingSuccess('getServiceDependencies'));
        }
    };
