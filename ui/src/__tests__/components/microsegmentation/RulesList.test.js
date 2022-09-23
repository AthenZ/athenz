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
import { waitFor } from '@testing-library/react';
import {
    buildMicrosegmentationForState,
    getStateWithMicrosegmentation,
    renderWithRedux,
} from '../../../tests_utils/ComponentsTestUtils';
import MockApi from '../../../mock/MockApi';
import RulesList from '../../../components/microsegmentation/RulesList';

describe('RulesList', () => {
    it('should render', () => {
        let domain = 'domain';
        let segmentationData = {
            inbound: [
                {
                    source_service: 'serviceA',
                    source_port: '1111',
                    destination_port: '2222',
                    destination_services: ['serviceB', 'serviceC', 'serviceD'],
                    layer: 'tcp',
                },
            ],
            outbound: [
                {
                    source_service: 'serviceE',
                    source_port: '3333',
                    destination_port: '4444',
                    destination_services: ['serviceF', 'serviceG', 'serviceH'],
                    layer: 'udp',
                },
            ],
        };

        const { getByTestId } = renderWithRedux(
            <RulesList
                domain={domain}
                _csrf={'_csrf'}
                isDomainAuditEnabled={true}
            />,
            getStateWithMicrosegmentation(
                buildMicrosegmentationForState(segmentationData, domain)
            )
        );

        const rulesList = getByTestId('segmentation-data-list');

        expect(rulesList).toMatchSnapshot();
    });
});
