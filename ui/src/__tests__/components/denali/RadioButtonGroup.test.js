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
import { fireEvent, render } from '@testing-library/react';
import RadioButtonGroup from '../../../components/denali/RadioButtonGroup';

describe('RadioButtonGroup', () => {
    const onChange = jest.fn();

    afterEach(() => onChange.mockClear());

    const inputs = [
        {
            label: 'Radio A',
            value: 'a',
        },
        {
            label: 'Radio B',
            value: 'b',
        },
        {
            label: 'Radio C',
            value: 'c',
            disabled: true,
        },
    ];

    it('should render', () => {
        const { getByTestId } = render(
            <RadioButtonGroup
                inputs={inputs}
                name='test-radiobuttongroup'
                selectedValue=''
                onChange={onChange}
            />
        );
        const wrapper = getByTestId('radiobuttongroup');
        const buttons = wrapper.querySelectorAll('.denali-radiobutton input');

        expect(wrapper).toMatchSnapshot();
        expect(buttons.length).toBe(3);
        expect(buttons[0]).not.toHaveAttribute('checked');
        expect(buttons[1]).not.toHaveAttribute('checked');
        expect(buttons[2]).not.toHaveAttribute('checked');
        expect(buttons[2]).toBeDisabled();
    });

    it('should render with selectedValue', () => {
        const { getByTestId } = render(
            <RadioButtonGroup
                inputs={inputs}
                name='test-radiobuttongroup'
                selectedValue='b'
                onChange={onChange}
            />
        );
        const wrapper = getByTestId('radiobuttongroup');
        const buttons = wrapper.querySelectorAll('.denali-radiobutton input');

        expect(buttons[0]).not.toHaveAttribute('checked');
        expect(buttons[1]).toHaveAttribute('checked');
        expect(buttons[2]).not.toHaveAttribute('checked');
    });

    it('should render all buttons as disabled', () => {
        const { getByTestId } = render(
            <RadioButtonGroup
                disabled
                inputs={inputs}
                name='test-radiobuttongroup'
                selectedValue='b'
                onChange={onChange}
            />
        );
        const wrapper = getByTestId('radiobuttongroup');
        const buttons = wrapper.querySelectorAll('.denali-radiobutton input');

        expect(buttons[0]).toBeDisabled();
        expect(buttons[1]).toBeDisabled();
        expect(buttons[2]).toBeDisabled();
    });

    it('should render vertical radio button group', () => {
        const { getByTestId } = render(
            <RadioButtonGroup
                direction='vertical'
                inputs={inputs}
                name='test-radiobuttongroup'
                selectedValue=''
                onChange={onChange}
            />
        );
        const wrapper = getByTestId('radiobuttongroup');

        expect(wrapper).toMatchSnapshot();
    });

    it('should render with an additional class name', () => {
        const { getByTestId } = render(
            <RadioButtonGroup
                className='custom-class'
                inputs={inputs}
                name='test-radiobuttongroup'
                selectedValue=''
                onChange={onChange}
            />
        );
        const wrapper = getByTestId('radiobuttongroup');

        expect(wrapper).toHaveClass('denali-radiobutton-group');
        expect(wrapper).toHaveClass('custom-class');
    });

    it('should handle onChange event)', () => {
        const { getByTestId } = render(
            <RadioButtonGroup
                disabled
                inputs={inputs}
                name='test-radiobuttongroup'
                selectedValue='b'
                onChange={onChange}
            />
        );
        const wrapper = getByTestId('radiobuttongroup');
        const buttons = wrapper.querySelectorAll('.denali-radiobutton input');

        fireEvent.click(buttons[0]);
        fireEvent.click(buttons[1]);
        fireEvent.click(buttons[2]);
        expect(onChange).toHaveBeenCalledTimes(2);
    });
});
