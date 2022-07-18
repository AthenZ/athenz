import { loadingInProcess, loadingSuccess } from '../../actions/loading';
import { getExpiryTime, listToMap } from '../../utils';
import API from '../../../api';
import { loadServices } from '../../actions/services';

const api = API();

export const getServicesApiCall = async (domainName, dispatch) => {
    try {
        dispatch(loadingInProcess('getServices'));
        const serviceList = await api.getServices(domainName, true, true);
        const expiry = getExpiryTime();
        for (let service of serviceList) {
            service.publicKeys = service.publicKeys
                ? listToMap(service.publicKeys, 'id')
                : {};
            service.expiry = expiry;
        }
        let serviceMap = listToMap(serviceList, 'name');
        dispatch(loadServices(serviceMap, domainName, expiry));
        dispatch(loadingSuccess('getServices'));
    } catch (error) {
        console.log('error: ', error);
    }
};
