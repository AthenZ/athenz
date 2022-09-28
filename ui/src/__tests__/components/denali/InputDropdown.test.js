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
import { fireEvent, render, waitFor } from '@testing-library/react';
import InputDropdown from '../../../components/denali/InputDropdown';

import _ from 'lodash';
import { resetIdCounter } from 'downshift';

jest.unmock('lodash');

_.debounce = jest.fn((fn) => fn);

// jest.mock('popper.js', () => {
//     const PopperJS = jest.requireActual('popper.js');
//
//     return class {
//         static placements = PopperJS.placements;
//
//         constructor() {
//             return {
//                 destroy: () => {},
//                 scheduleUpdate: () => {},
//             };
//         }
//     };
// });

describe('InputDropdown', () => {
    beforeEach(() => {
        resetIdCounter();
    });
    const onChange = jest.fn();
    const options = [
        { value: 'astonmartin', name: 'Aston Martin DBS Superleggera' },
        { value: 'chiron', name: 'Bugatti Chiron' },
        { value: 'veyron', name: 'Bugatti Veyron' },
        { value: 'ferrari', name: 'Ferrari 488 GTB' },
        { value: 'hennessey', name: 'Hennessey Venom F5' },
    ];
    const asyncSearchFunc = jest.fn(async (searchTerm) => {
        const regexp = new RegExp(searchTerm, 'i');
        return options.filter((o) => o.name.search(regexp) > -1);
    });

    afterEach(() => jest.clearAllMocks());

    it('renders initial (closed) state', () => {
        const { baseElement, container, getByTestId } = render(
            <InputDropdown name='test' options={options} onChange={onChange} />
        );
        const inputDropdown = getByTestId('input-dropdown');
        const inputNode = getByTestId('input-node');

        expect(
            baseElement.querySelector('.denali-input-dropdown-options')
        ).toBeNull();

        expect(inputDropdown).toMatchSnapshot();
        expect(inputNode).toHaveAttribute('readonly');
        expect(inputNode.value).toBe('');
        // expect(container.querySelector('.arrow')).not.toBeNull();
        // expect(container.querySelector('.clear-selection')).toBeNull();
    });

    it('renders fluid dropdown', () => {
        const { getByTestId } = render(
            <InputDropdown
                fluid
                name='test'
                options={options}
                onChange={onChange}
            />
        );
        const inputDropdown = getByTestId('input-dropdown');
        const inputWrapper = getByTestId('input-wrapper');

        expect(inputDropdown).toMatchSnapshot();
        expect(inputDropdown).toHaveStyle(`width: 100%`);
        expect(inputWrapper).toHaveStyle(`width: 100%`);
    });

    it('renders with default selected item', () => {
        const defaultSelectedItem = { value: 'chiron', name: 'Bugatti Chiron' };
        const { container, getByTestId } = render(
            <InputDropdown
                name='test'
                options={options}
                defaultSelectedItem={defaultSelectedItem}
                onChange={onChange}
            />
        );
        const inputNode = getByTestId('input-node');

        expect(inputNode.value).toBe('Bugatti Chiron');
        // expect(container.querySelector('.clear-selection')).not.toBeNull();
    });

    it('renders with default selected value', () => {
        const { container, getByTestId } = render(
            <InputDropdown
                name='test'
                options={options}
                defaultSelectedValue='veyron'
                onChange={onChange}
            />
        );
        const inputNode = getByTestId('input-node');

        expect(inputNode.value).toBe('Bugatti Veyron');
        // expect(container.querySelector('.clear-selection')).not.toBeNull();
    });

    it('renders with default selected name', () => {
        const { container, getByTestId } = render(
            <InputDropdown
                name='test'
                options={options}
                defaultSelectedName='Ferrari 488 GTB'
                onChange={onChange}
            />
        );
        const inputNode = getByTestId('input-node');

        expect(inputNode.value).toBe('Ferrari 488 GTB');
        // expect(container.querySelector('.clear-selection')).not.toBeNull();
    });

    it('disables clearing selection with noclear prop', () => {
        const { container, getByTestId } = render(
            <InputDropdown
                name='test'
                options={options}
                defaultSelectedName='Ferrari 488 GTB'
                noclear
                onChange={onChange}
            />
        );
        const inputNode = getByTestId('input-node');

        expect(inputNode.value).toBe('Ferrari 488 GTB');
        expect(container.querySelector('.clear-selection')).toBeNull();
    });

    it('should render with an additional class name', () => {
        const { container, getByTestId } = render(
            <InputDropdown
                className='custom-class'
                name='test'
                options={options}
                defaultSelectedName='Ferrari 488 GTB'
                noclear
                onChange={onChange}
            />
        );
        const inputDiv = getByTestId('input-dropdown');

        expect(inputDiv).toHaveClass('custom-class');
        expect(container.querySelector('.clear-selection')).toBeNull();
    });

    it('opens the dropdown', async () => {
        const { baseElement, getByTestId } = render(
            <InputDropdown name='test' options={options} onChange={onChange} />
        );
        const inputNode = getByTestId('input-node');
        const inputDropdown = getByTestId('input-dropdown');

        expect(
            baseElement.querySelector('.denali-input-dropdown-options')
        ).toBeNull();

        fireEvent.click(inputNode);

        await waitFor(() =>
            baseElement.querySelector('.denali-input-dropdown-options')
        );

        expect(inputDropdown).toMatchSnapshot();
        expect(baseElement.querySelectorAll('.dropdown-item').length).toBe(5);
    });

    it('handles preventing scroll', async () => {
        const onParentScroll = jest.fn();

        const { baseElement, getByTestId } = render(
            <div onScroll={onParentScroll} data-testid='parent-div'>
                <InputDropdown
                    name='test'
                    options={options}
                    onChange={onChange}
                />
            </div>
        );
        const inputNode = getByTestId('input-node');

        fireEvent.click(inputNode);

        const dropdownOptionsWrapper = await waitFor(() =>
            baseElement.querySelector('.denali-input-dropdown-options')
        );

        fireEvent.scroll(dropdownOptionsWrapper);

        expect(onParentScroll).not.toHaveBeenCalled();
    });

    it('can open and select a menu item', async () => {
        const { baseElement, container, getByTestId } = render(
            <InputDropdown name='test' options={options} onChange={onChange} />
        );
        const inputNode = getByTestId('input-node');

        fireEvent.click(inputNode);

        await waitFor(() =>
            baseElement.querySelector('.denali-input-dropdown-options')
        );
        const dropdownOptions = baseElement.querySelectorAll('.dropdown-item');
        expect(
            baseElement.querySelector('.denali-input-dropdown-options')
        ).toHaveClass('animated');
        // Click second item
        fireEvent.click(dropdownOptions[1]);

        expect(onChange).toHaveBeenLastCalledWith({
            value: 'chiron',
            name: 'Bugatti Chiron',
        });

        await waitFor(() =>
            expect(
                baseElement.querySelector('.denali-input-dropdown-options')
            ).not.toBeInTheDocument()
        );

        expect(inputNode.value).toBe('Bugatti Chiron');
        // expect(container.querySelector('.clear-selection')).not.toBeNull();
    });

    it('can clear a selection', () => {
        const defaultSelectedItem = { value: 'chiron', name: 'Bugatti Chiron' };
        const { container, getByTestId } = render(
            <InputDropdown
                name='test'
                options={options}
                defaultSelectedItem={defaultSelectedItem}
                onChange={onChange}
            />
        );
        const inputNode = getByTestId('input-node');
        const clearButton = container.querySelector('.clear-selection');

        expect(inputNode.value).toBe('Bugatti Chiron');
        // expect(clearButton).not.toBeNull();

        // Clear selection
        // fireEvent.click(clearButton);
        // expect(onChange).toHaveBeenLastCalledWith(null);
        //
        // expect(inputNode.value).toBe('');
    });

    it('handles not selecting an item', async () => {
        const { baseElement, getByTestId } = render(
            <InputDropdown name='test' options={options} onChange={onChange} />
        );
        const inputNode = getByTestId('input-node');

        fireEvent.click(inputNode);

        await waitFor(() =>
            baseElement.querySelector('.denali-input-dropdown-options')
        );

        // Close dropdown by hitting Esc
        fireEvent.keyDown(inputNode, { keyCode: 27 });

        await waitFor(() =>
            expect(
                baseElement.querySelector('.denali-input-dropdown-options')
            ).not.toBeInTheDocument()
        );

        expect(onChange).not.toHaveBeenCalled();
        expect(inputNode.value).toBe('');
    });

    it('highlights correct menu item', async () => {
        const defaultSelectedItem = {
            value: 'hennessey',
            name: 'Hennessey Venom F5',
        };
        const { baseElement, getByTestId } = render(
            <InputDropdown
                name='test'
                options={options}
                defaultSelectedItem={defaultSelectedItem}
                onChange={onChange}
            />
        );
        const inputNode = getByTestId('input-node');

        expect(inputNode.value).toBe('Hennessey Venom F5');

        fireEvent.click(inputNode);

        await waitFor(() =>
            baseElement.querySelector('.denali-input-dropdown-options')
        );

        expect(baseElement.querySelectorAll('.dropdown-item')[4]).toHaveClass(
            'selected'
        );
    });

    it('renders a filterable dropdown', async () => {
        const { baseElement, getByTestId } = render(
            <InputDropdown
                name='test'
                options={options}
                filterable
                onChange={onChange}
            />
        );
        const inputDropdown = getByTestId('input-dropdown');
        const inputNode = getByTestId('input-node');

        expect(inputDropdown).toMatchSnapshot();
        expect(inputNode).not.toHaveAttribute('readonly');

        fireEvent.click(inputNode);

        await waitFor(() =>
            baseElement.querySelector('.denali-input-dropdown-options')
        );

        let dropdownOptions = baseElement.querySelectorAll('.dropdown-item');
        expect(dropdownOptions.length).toBe(5);

        // Type 'Bug' narrow down items
        fireEvent.change(inputNode, { target: { value: 'Bug' } });

        expect(inputNode.value).toBe('Bug');
        dropdownOptions = baseElement.querySelectorAll('.dropdown-item');
        expect(dropdownOptions.length).toBe(2);

        // Enter search term that yields no results
        fireEvent.change(inputNode, { target: { value: 'meh' } });

        dropdownOptions = baseElement.querySelectorAll('.dropdown-item');
        expect(dropdownOptions.length).toBe(0);
        expect(baseElement.querySelector('.no-items')).not.toBeNull();
    });

    it('renders searchable input', () => {
        const { baseElement, container, getByTestId } = render(
            <InputDropdown
                name='test'
                asyncSearchFunc={asyncSearchFunc}
                onChange={onChange}
            />
        );
        const inputDropdown = getByTestId('input-dropdown');
        const inputNode = getByTestId('input-node');

        expect(inputDropdown).toMatchSnapshot();
        expect(
            baseElement.querySelector('.denali-input-dropdown-options')
        ).not.toBeInTheDocument();
        expect(inputNode).not.toHaveAttribute('readonly');
        expect(inputNode.value).toBe('');
        expect(container.querySelector('.arrow')).toBeNull();
        expect(container.querySelector('.clear-selection')).toBeNull();
    });

    it('handles searching', async () => {
        const { baseElement, getByTestId, queryByText } = render(
            <InputDropdown
                name='test'
                asyncSearchFunc={asyncSearchFunc}
                onChange={onChange}
            />
        );
        const inputNode = getByTestId('input-node');

        // Enter one character, which should not trigger search
        fireEvent.change(inputNode, { target: { value: 'b' } });

        expect(
            baseElement.querySelector('.denali-input-dropdown-options')
        ).not.toBeInTheDocument();
        expect(asyncSearchFunc).not.toHaveBeenCalled();

        // Enter search term that yields no results
        fireEvent.change(inputNode, { target: { value: 'meh' } });

        await waitFor(() => queryByText('Loading...'));
        expect(asyncSearchFunc).toHaveBeenLastCalledWith('meh');

        expect(baseElement.querySelectorAll('.dropdown-item').length).toBe(0);
        await waitFor(() =>
            expect(baseElement.querySelector('.no-items.empty')).not.toBeNull()
        );

        // Enter search term that yields two results
        fireEvent.change(inputNode, { target: { value: 'bug' } });

        expect(baseElement.querySelector('.no-items.loading')).not.toBeNull();
        expect(asyncSearchFunc).toHaveBeenLastCalledWith('bug');

        await waitFor(() =>
            expect(baseElement.querySelectorAll('.dropdown-item').length).toBe(
                2
            )
        );

        expect(baseElement.querySelector('.no-items')).toBeNull();
    });

    it('handles error from search', async () => {
        const asyncSearchFunc = jest.fn(() =>
            Promise.reject(new Error('uh oh'))
        );
        const { baseElement, getByTestId } = render(
            <InputDropdown
                name='test'
                asyncSearchFunc={asyncSearchFunc}
                onChange={onChange}
            />
        );
        const inputNode = getByTestId('input-node');

        fireEvent.change(inputNode, { target: { value: 'bug' } });

        await waitFor(() =>
            baseElement.querySelector('.denali-input-dropdown-options')
        );
        await waitFor(() =>
            expect(baseElement.querySelector('.no-items.error')).not.toBeNull()
        );
    });

    it('handles null from search (cancellation)', async () => {
        const asyncSearchFunc = jest.fn(() => Promise.resolve(null));
        const { baseElement, getByTestId } = render(
            <InputDropdown
                name='test'
                asyncSearchFunc={asyncSearchFunc}
                onChange={onChange}
            />
        );
        const inputNode = getByTestId('input-node');

        fireEvent.change(inputNode, { target: { value: 'bug' } });

        expect(baseElement.querySelector('.no-items.loading')).not.toBeNull();

        await waitFor(() =>
            expect(
                baseElement.querySelector('.no-items.loading')
            ).toBeInTheDocument()
        );
    });

    it('can disable transitions', async () => {
        const { baseElement, getByTestId } = render(
            <InputDropdown
                name='test'
                noanim
                options={options}
                onChange={onChange}
            />
        );
        const inputNode = getByTestId('input-node');

        fireEvent.click(inputNode);

        await waitFor(() =>
            baseElement.querySelector('.denali-input-dropdown-options')
        );
        expect(
            baseElement.querySelector('.denali-input-dropdown-options')
        ).not.toHaveClass('animated');
    });
});
