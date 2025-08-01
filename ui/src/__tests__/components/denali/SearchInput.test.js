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
import { render, fireEvent } from '@testing-library/react';
import SearchInput from '../../../components/denali/SearchInput';

describe('SearchInput', () => {
    it('should render', () => {
        const onChange = jest.fn();
        const { getByTestId } = render(
            <SearchInput
                name='search'
                placeholder='Search!'
                value=''
                onChange={onChange}
            />
        );
        const wrapper = getByTestId('input-wrapper');
        const inputNode = getByTestId('input-node');

        expect(wrapper).toMatchSnapshot();
        expect(wrapper.querySelector('.input-icon')).not.toBeNull();
        expect(inputNode).toHaveAttribute('placeholder', 'Search!');
    });

    it('should call onSearch when search icon is clicked', () => {
        const onChange = jest.fn();
        const onSearch = jest.fn();
        const { getByTestId } = render(
            <SearchInput
                name='search'
                placeholder='Search!'
                value=''
                onChange={onChange}
                onSearch={onSearch}
            />
        );
        const wrapper = getByTestId('input-wrapper');
        // Find the div that has the onClick handler (the one with cursor: pointer style)
        const searchIconContainer = wrapper.querySelector('.input-icon[style*="cursor: pointer"]');

        fireEvent.click(searchIconContainer);
        expect(onSearch).toHaveBeenCalledTimes(1);
    });

    it('should not call onSearch when search icon is clicked without onSearch prop', () => {
        const onChange = jest.fn();
        const { getByTestId } = render(
            <SearchInput
                name='search'
                placeholder='Search!'
                value=''
                onChange={onChange}
            />
        );
        const wrapper = getByTestId('input-wrapper');
        const searchIconContainer = wrapper.querySelector('.input-icon');

        // This should not throw an error
        expect(() => fireEvent.click(searchIconContainer)).not.toThrow();
    });
});
