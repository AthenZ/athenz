import { loadingInProcess, loadingSuccess } from '../../actions/loading';
import { getExpiryTime, listToMap } from '../../utils';
import API from '../../../api';
import { loadServices } from '../../actions/services';

export const getServicesApiCall = async (domainName, dispatch) => {
    dispatch(loadingInProcess('getServices'));
    const serviceList = await API().getServices(domainName, true, true);
    const expiry = getExpiryTime();
    for (let service of serviceList) {
        service.publicKeys = service.publicKeys
            ? listToMap(service.publicKeys, 'id')
            : {};
    }
    let serviceMap = listToMap(serviceList, 'name');
    dispatch(loadServices(serviceMap, domainName, expiry));
    dispatch(loadingSuccess('getServices'));
};
