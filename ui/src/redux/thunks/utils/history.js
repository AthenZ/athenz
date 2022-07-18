import API from '../../../api';
import { getHistory } from '../history';
import { loadHistory } from '../../actions/history';
import { loadingInProcess, loadingSuccess } from '../../actions/loading';
import { getExpiryTime } from '../../utils';

const api = API();

export const getHistoryApiCall = async (
    domainName,
    roleName,
    startDate,
    endDate,
    dispatch
) => {
    dispatch(loadingInProcess('getHistory'));
    const domainHistory = await api.getHistory(
        domainName,
        roleName,
        startDate,
        endDate
    );
    const expiry = getExpiryTime();
    dispatch(loadHistory(domainHistory, domainName, expiry));
    dispatch(loadingSuccess('getHistory'));
};
