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
import NavBarItem from '../../../components/denali/NavBarItem';

describe('NavBarItem', () => {
    it('should render a basic item', () => {
        const { getByTestId } = render(<NavBarItem>An item</NavBarItem>);
        const navbarItem = getByTestId('navbar-item');

        expect(navbarItem).toMatchSnapshot();
    });

    it('should render a link item', () => {
        const { getByTestId } = render(<NavBarItem link>An item</NavBarItem>);
        const navbarItem = getByTestId('navbar-item');

        expect(navbarItem).toMatchSnapshot();
        expect(navbarItem).toHaveClass('nav-link');
    });

    it('should render an active item', () => {
        const { getByTestId } = render(<NavBarItem active>An item</NavBarItem>);
        const navbarItem = getByTestId('navbar-item');

        expect(navbarItem).toMatchSnapshot();
        expect(navbarItem).toHaveClass('active');
    });

    it('should render an active link item', () => {
        const { getByTestId } = render(
            <NavBarItem active link>
                An item
            </NavBarItem>
        );
        const navbarItem = getByTestId('navbar-item');

        expect(navbarItem).toMatchSnapshot();
        expect(navbarItem).toHaveClass('active');
        expect(navbarItem).toHaveClass('nav-link');
    });

    it('should render a right-aligned item', () => {
        const { getByTestId } = render(<NavBarItem right>An item</NavBarItem>);
        const navbarItem = getByTestId('navbar-item');

        expect(navbarItem).toMatchSnapshot();
        expect(navbarItem).toHaveClass('flush-right');
    });

    it('should render an item with width', () => {
        const { getByTestId } = render(
            <NavBarItem width='100px'>An item</NavBarItem>
        );
        const navbarItem = getByTestId('navbar-item');

        expect(navbarItem).toMatchSnapshot();
        expect(navbarItem).toHaveStyle(`width: 100px`);
    });

    it('should render a complex item', () => {
        const { getByTestId } = render(
            <NavBarItem complex>
                <div className='complex-item'>
                    <div className='nav-title' data-testid='navbar-text'>
                        A complex item
                    </div>
                </div>
            </NavBarItem>
        );
        const navbarItem = getByTestId('navbar-item');

        expect(navbarItem).toMatchSnapshot();
    });

    it('should render a complex active link item', () => {
        const { getByTestId } = render(
            <NavBarItem complex active link>
                <div className='complex-item'>
                    <div className='nav-title' data-testid='navbar-text'>
                        A complex active link item
                    </div>
                </div>
            </NavBarItem>
        );
        const navbarItem = getByTestId('navbar-item');

        expect(navbarItem).toMatchSnapshot();
        expect(navbarItem).toHaveClass('active');
        expect(navbarItem).toHaveClass('nav-link');
    });

    it('should disable animations', () => {
        const { getByTestId } = render(<NavBarItem noanim>An item</NavBarItem>);
        const navbarItem = getByTestId('navbar-item');

        expect(navbarItem).toMatchSnapshot();
    });

    it('should render with an additional class name', () => {
        const { getByTestId } = render(
            <NavBarItem className='custom-class'>An item</NavBarItem>
        );
        const navbarItem = getByTestId('navbar-item');

        expect(navbarItem).toHaveClass('denali-navbar-item');
        expect(navbarItem).toHaveClass('custom-class');
    });
});
