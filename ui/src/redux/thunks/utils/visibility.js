import { loadServiceDependencies } from '../../actions/visibility';
import { loadingInProcess, loadingSuccess } from '../../actions/loading';
import { getExpiryTime } from '../../utils';
import API from '../../../api';
import ApiFactory from '../../ApiFactory';

const getApi = (() => {
    let api;
    return () => {
        if (api) {
            return api;
        }
        api = API();
        return api;
    }
})();

export const getServiceDependenciesApiCall = async (domainName, dispatch) => {
    dispatch(loadingInProcess('getServiceDependencies'));
    const serviceDependencies = await getApi().getServiceDependencies(
        domainName
    );
    const expiry = getExpiryTime();
    dispatch(loadServiceDependencies(serviceDependencies, domainName, expiry));
    dispatch(loadingSuccess('getServiceDependencies'));
};
