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
import MemberTable from '../../../components/member/MemberTable';
import API from '../../../api';
import RuleTable from "../../../components/microsegmentation/RuleTable";

describe('RuleTable', () => {
    it('should render rule table', () => {
        let domain= 'domain';
        let data = [
            {
                "source_service": "serviceA",
                "source_port": "1111",
                "destination_port": "2222",
                "destination_services": [
                    "serviceB",
                    "serviceC",
                    "serviceD"
                ],
                "layer" : "tcp"
            }
        ]

        const { getByTestId } = render(
            <RuleTable
                category={'inbound'}
                domain={domain}
                api={API()}
                _csrf={"_csrf"}
                data={data}
                caption='Inbound'
            />
        );
        const ruleTable = getByTestId('segmentation-rule-table');

        expect(ruleTable).toMatchSnapshot();
    });
});
