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
import Loader from '../../../components/denali/Loader';

describe('Loader', () => {
    it('should render', () => {
        const { container } = render(<Loader />);
        const svg = container.querySelector('svg');

        expect(svg).not.toBeNull();
        expect(svg).toHaveClass('denali-loader');
    });

    it('should render with different size, color, and verticalAlign', () => {
        const { container } = render(
            <Loader size='2em' color='red' verticalAlign='top' />
        );
        const svg = container.querySelector('svg');
        const path = container.querySelector('path');

        expect(svg).toHaveStyle(
            `vertical-align: top; width: 2em; height: 2em;`
        );
        expect(path).toHaveAttribute('stroke', 'red');
    });

    it('should render with additional className', () => {
        const { container } = render(<Loader className='custom-class' />);
        const svg = container.querySelector('svg');

        expect(svg).toHaveClass('denali-loader');
        expect(svg).toHaveClass('custom-class');
    });
});
