import { loadServiceDependencies } from '../../actions/visibility';
import { loadingInProcess, loadingSuccess } from '../../actions/loading';
import { getExpiryTime } from '../../utils';
import API from '../../../api';

export const getServiceDependenciesApiCall = async (domainName, dispatch) => {
    dispatch(loadingInProcess('getServiceDependencies'));
    const serviceDependencies = await API().getServiceDependencies(domainName);
    const expiry = getExpiryTime();
    dispatch(loadServiceDependencies(serviceDependencies, domainName, expiry));
    dispatch(loadingSuccess('getServiceDependencies'));
};
