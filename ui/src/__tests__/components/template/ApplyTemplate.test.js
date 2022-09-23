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
import ApplyTemplate from '../../../components/template/ApplyTemplate';
import { colors } from '../../../components/denali/styles';

describe('ApplyTemplate', () => {
    function onClickUpdateTemplate() {
        return false;
    }

    it('should render', () => {
        const showApplyTemplate = true;
        const onSubmit = onClickUpdateTemplate;
        const onCancel = onClickUpdateTemplate;
        const keywordsList = '';
        const { getByTestId } = render(
            <table>
                <tbody>
                    <ApplyTemplate
                        keywords={keywordsList}
                        showApplyTemplate={showApplyTemplate}
                        onSubmit={onSubmit}
                        onCancel={onCancel}
                    />
                </tbody>
            </table>
        );
        const applyTemplate = getByTestId('add-service-form');
        expect(applyTemplate).toMatchSnapshot();
    });

    it('should render with keywords', () => {
        const color = colors.row;
        const item = '_service_';
        const showApplyTemplate = true;
        const onSubmit = onClickUpdateTemplate;
        const onCancel = onClickUpdateTemplate;
        const keywordsList = '_service_';
        const templateName = 'aws';
        const domain = 'testdom';
        const api = {
            updateTemplate: function (params, csrf) {
                return new Promise((resolve, reject) => {
                    resolve([]);
                });
            },
        };

        const { getByTestId } = render(
            <table>
                <tbody>
                    <ApplyTemplate
                        item={item}
                        keywords={keywordsList}
                        showApplyTemplate={showApplyTemplate}
                        onSubmit={onSubmit}
                        onCancel={onCancel}
                        api={api}
                        domain={domain}
                        templateName={templateName}
                    />
                </tbody>
            </table>
        );
        const applyTemplate = getByTestId('add-service-form');
        expect(applyTemplate).toMatchSnapshot();
    });
});
