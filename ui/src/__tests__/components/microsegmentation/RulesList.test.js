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
        // const policies = []
        // policies.push({
        //     name: 'domain:policy.acl.serviceB.inbound',
        //     version: '0',
        //     active: true,
        //     assertion: [
        //         {
        //             role: 'domain:role.acl.serviceB.inbound-test0',
        //             id: 0,
        //             effect: 'ALLOW',
        //             resource: 'domain:serviceB',
        //             action: 'TCP-IN:1111:2222-2222',
        //         },
        //     ],
        // })
        // policies.push({
        //     name: 'domain:policy.acl.serviceC.inbound',
        //     version: '0',
        //     active: true,
        //     assertion: [
        //         {
        //             role: 'domain:role.acl.serviceC.inbound-test1',
        //             id: 1,
        //             effect: 'ALLOW',
        //             resource: 'domain:serviceC',
        //             action: 'TCP-IN:1111:2222-2222',
        //         },
        //     ],
        // })
        // policies.push({
        //     name: 'domain:policy.acl.serviceD.inbound',
        //     version: '0',
        //     active: true,
        //     assertion: [
        //         {
        //             role: 'domain:role.acl.serviceD.inbound-test2',
        //             id: 2,
        //             effect: 'ALLOW',
        //             resource: 'domain:serviceD',
        //             action: 'TCP-IN:1111:2222-2222',
        //         },
        //     ],
        // })
        // policies.push({
        //     name: 'domain:policy.acl.serviceF.outbound',
        //     version: '0',
        //     active: true,
        //     assertion: [
        //         {
        //             role: 'domain:role.acl.serviceF.outbound-test3',
        //             id: 3,
        //             effect: 'ALLOW',
        //             resource: 'domain:serviceF',
        //             action: 'UDP-OUT:3333:4444-4444',
        //         },
        //     ],
        // })
        // policies.push({
        //     name: 'domain:policy.acl.serviceG.outbound',
        //     version: '0',
        //     active: true,
        //     assertion: [
        //         {
        //             role: 'domain:role.acl.serviceG.outbound-test4',
        //             id: 4,
        //             effect: 'ALLOW',
        //             resource: 'domain:serviceG',
        //             action: 'UDP-OUT:3333:4444-4444',
        //         },
        //     ],
        // })
        // policies.push({
        //     name: 'domain:policy.acl.serviceH.outbound',
        //     version: '0',
        //     active: true,
        //     assertion: [
        //         {
        //             role: 'domain:role.acl.serviceH.outbound-test5',
        //             id: 5,
        //             effect: 'ALLOW',
        //             resource: 'domain:serviceH',
        //             action: 'UDP-OUT:3333:4444-4444',
        //         },
        //     ],
        // })
        //
        // const roles = [];
        // roles.push({
        //     name: 'domain:role.acl.serviceB.inbound-test0',
        //     roleMembers: [
        //         { memberName: 'serviceA' },
        //     ],
        // });
        // roles.push({
        //     name: 'domain:role.acl.serviceC.inbound-test1',
        //     roleMembers: [
        //         { memberName: 'serviceA' },
        //     ],
        // });
        // roles.push({
        //     name: 'domain:role.acl.serviceD.inbound-test2',
        //     roleMembers: [
        //         { memberName: 'serviceA' },
        //     ],
        // });
        // roles.push({
        //     name: 'domain:role.acl.serviceF.outbound-test3',
        //     roleMembers: [
        //         { memberName: 'serviceE' },
        //     ],
        // });
        // roles.push({
        //     name: 'domain:role.acl.serviceG.outbound-test4',
        //     roleMembers: [
        //         { memberName: 'serviceE' },
        //     ],
        // });
        // roles.push({
        //     name: 'domain:role.acl.serviceH.outbound-test5',
        //     roleMembers: [
        //         { memberName: 'serviceE' },
        //     ],
        // });


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
            getStateWithMicrosegmentation(buildMicrosegmentationForState(segmentationData, domain))
        );

        const rulesList = getByTestId('segmentation-data-list');

        expect(rulesList).toMatchSnapshot();
    });
});
