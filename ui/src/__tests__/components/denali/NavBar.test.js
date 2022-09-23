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
import NavBar from '../../../components/denali/NavBar';

describe('NavBar', () => {
    it('should render', () => {
        const { getByTestId } = render(<NavBar />);
        const navbar = getByTestId('navbar');

        expect(navbar).toMatchSnapshot();
    });

    it('should render with background prop', () => {
        const { getByTestId } = render(<NavBar background='blue' />);
        const navbar = getByTestId('navbar');

        expect(navbar).toMatchSnapshot();
        expect(navbar).toHaveStyle(`background: blue`);
    });

    it('should render with position prop', () => {
        const { getByTestId } = render(<NavBar position='sticky' />);
        const navbar = getByTestId('navbar');

        expect(navbar).toMatchSnapshot();
        expect(navbar).toHaveStyle(`position: sticky`);
    });

    it('should render with an additional class name', () => {
        const { getByTestId } = render(<NavBar className='custom-class' />);
        const navbar = getByTestId('navbar');

        expect(navbar).toHaveClass('denali-navbar');
        expect(navbar).toHaveClass('custom-class');
    });
});
