/*
 * Copyright 2020 Verizon Media
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
import TemplateDescription from '../../../components/template/TemplateDescription';
import { colors } from '../../../components/denali/styles';

describe('TemplateDescription', () => {
    it('should render', () => {
        const color = colors.row;
        const description = "test description";
        const { getByTestId } = render(
            <table>
                <tbody>
                <TemplateDescription description={description} color={{color}} />
                </tbody>
            </table>
        );
        const TemplateDesc = getByTestId('provider-table');
        expect(TemplateDesc).toMatchSnapshot();
    });
});
