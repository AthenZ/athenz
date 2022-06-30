import API from '../../api';
import { loadingInProcess, loadingSuccess } from '../actions/loading';
import { loadHistory, returnHistory } from '../actions/history';
import { storeHistory } from '../actions/domains';
import { getExpiryTime } from '../utils';

const api = API();

export const getHistory =
    (domainName, roleName, startDate, endDate) =>
    async (dispatch, getState) => {
        console.log('getHistory called!!!');
        if (getState().domainHistory.expiry) {
            if (getState().domainHistory.domainName !== domainName) {
                dispatch(loadingInProcess('getHistory'));
                dispatch(storeHistory(getState().domainHistory));
                if (
                    getState().domains[domainName] &&
                    getState().domains[domainName].domainHistory &&
                    getState().domains[domainName].domainHistory.expiry > 0
                ) {
                    dispatch(
                        loadHistory(
                            getState().domains[domainName].domainHistory,
                            domainName,
                            getState().domains[domainName].domainHistory.expiry
                        )
                    );
                } else {
                    const domainHistory = await api.getHistory(
                        domainName,
                        roleName,
                        startDate,
                        endDate
                    );
                    dispatch(loadHistory(domainHistory));
                    dispatch(loadingSuccess('getHistory'));
                }
            } else if (getState().domainHistory.expiry <= 0) {
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
            } else {
                dispatch(returnHistory());
            }
        } else {
            dispatch(loadingInProcess('getHistory'));
            console.log('about to loadHistory for domain:', domainName);
            const domainHistory = await api.getHistory(
                domainName,
                roleName,
                startDate,
                endDate
            );
            console.log('loadHistory success', domainHistory);
            const expiry = getExpiryTime();
            dispatch(loadHistory(domainHistory, domainName, expiry));
            dispatch(loadingSuccess('getHistory'));
        }
    };
