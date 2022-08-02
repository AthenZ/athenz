import { domainName, storeInboundOutboundList } from '../../config/config.test';
import { selectInboundOutboundList } from '../../../redux/selectors/microsegmentation';
import { _ } from 'lodash';

describe('test selectInboundOutboundList', () => {
    it('should return inboundOutboundList', () => {
        const state = {
            microsegmentation: {
                inboundOutboundList: storeInboundOutboundList,
                domainName,
            },
        };
        expect(
            _.isEqual(
                selectInboundOutboundList(state),
                storeInboundOutboundList
            )
        ).toBeTruthy();
    });
    it('should return empty list', () => {
        const state = {
            microsegmentation: {},
        };
        expect(selectInboundOutboundList(state)).toEqual([]);
    });
});
