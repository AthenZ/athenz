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
import { colors } from '../../../components/denali/styles';
import ServiceList from '../../../components/microsegmentation/ServiceList';
import API from '../../../api';

describe('ServiceList', () => {
    it('should render', () => {
        let details = ['serviceB', 'serviceC', 'serviceD'];

        let domain = 'domain';
        const { getByTestId } = render(
            <table>
                <tbody>
                    <ServiceList list={details} domain={domain} />
                </tbody>
            </table>
        );
        const ruleRow = getByTestId('segmentation-service-list');

        expect(ruleRow).toMatchSnapshot();
    });
});
