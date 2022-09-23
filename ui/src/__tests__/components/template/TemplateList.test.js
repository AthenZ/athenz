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
import TemplateList from '../../../components/template/TemplateList';
import { renderWithRedux } from '../../../tests_utils/ComponentsTestUtils';

describe('TemplateList', () => {
    it('should render', () => {
        const { getByTestId } = renderWithRedux(<TemplateList />);
        const templatelist = getByTestId('template-list');

        expect(templatelist).toMatchSnapshot();
    });

    it('should render with metadata array', () => {
        const left = 'left';
        const center = 'center';
        let toReturn = [
            {
                templateName: 'aws',
                description: 'AWS access template',
                currentVersion: 4,
                latestVersion: 1,
                timestamp: '2020-04-28T00:00:00.000Z',
                autoUpdate: false,
            },
        ];

        const api = {
            updateTemplate: function (params, csrf) {
                return new Promise((resolve, reject) => {
                    resolve(toReturn);
                });
            },
        };

        const { getByTestId } = renderWithRedux(
            <TemplateList
                left={left}
                center={center}
                list={toReturn}
                serverTemplateDetails={toReturn}
                api={api}
            />
        );
        const templatelist = getByTestId('template-list');

        expect(templatelist).toMatchSnapshot();
    });
});
