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
import InputLabel from '../../../components/denali/InputLabel';

describe('InputLabel', () => {
    it('should render', () => {
        const { getByText } = render(<InputLabel>An InputLabel</InputLabel>);

        expect(getByText('An InputLabel').nodeName).toBe('LABEL');
    });

    it('should render input label for small input', () => {
        const { getByText } = render(
            <InputLabel size='small'>An InputLabel</InputLabel>
        );
        const label = getByText('An InputLabel');

        expect(label).toHaveStyle(`line-height: 28px`);
    });

    it('should render with an additional class name', () => {
        const { getByText } = render(
            <InputLabel className='custom-class'>An InputLabel</InputLabel>
        );
        const label = getByText('An InputLabel');

        expect(label).toHaveClass('denali-input-label');
        expect(label).toHaveClass('custom-class');
    });
});
