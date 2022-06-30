/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import React from 'react';
import { render } from '@testing-library/react';
import ServiceDependency from '../../../components/visibility/ServiceDependency';
import AuthHistory from '../../../components/visibility/AuthHistory';
import API from '../../../api';

describe('AuthHistory', () => {
    it('should render', () => {
        let dependencies = {
            incomingDependencies: [
                {
                    uriDomain: 'incomingUriDomain1',
                    principalDomain: 'incomingPrincDomain1',
                    principalName: 'incomingPrincName1',
                    timestamp: 'incomingTimestamp1',
                },
                {
                    uriDomain: 'incomingUriDomain2',
                    principalDomain: 'incomingPrincDomain2',
                    principalName: 'incomingPrincName2',
                    timestamp: 'incomingTimestamp2',
                },
            ],
            outgoingDependencies: [
                {
                    uriDomain: 'outgoingUriDomain1',
                    principalDomain: 'outgoingPrincDomain1',
                    principalName: 'outgoingPrincName1',
                    timestamp: 'outgoingTimestamp1',
                },
            ],
        };
        let domain = 'domain';
        const _csrf = '_csrf';
        const { getByTestId } = render(
            <AuthHistory
                key={'authHistoryView'}
                data-testid='authHistoryGraph'
                data={dependencies}
                api={API()}
                domain={domain}
                _csrf={_csrf}
            />
        );
        const dependenciestable = getByTestId('auth-history-table');

        expect(dependenciestable).toMatchSnapshot();
    });
});
