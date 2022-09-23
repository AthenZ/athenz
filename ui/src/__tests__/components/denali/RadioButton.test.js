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
import RadioButton from '../../../components/denali/RadioButton';

describe('RadioButton', () => {
    const onChange = jest.fn();

    afterEach(() => onChange.mockClear());

    it('should render unselected state', () => {
        const { getByLabelText, getByTestId } = render(
            <RadioButton
                checked={false}
                label='Option A'
                name='test-radiobutton'
                value='a'
                onChange={onChange}
            />
        );
        const wrapper = getByTestId('radiobutton-wrapper');
        const input = getByLabelText('Option A');

        expect(wrapper).toMatchSnapshot();
        expect(input).not.toHaveAttribute('checked');
        expect(input).toHaveAttribute('id', 'radiobutton-test-radiobutton-a');
    });

    it('should render selected state', () => {
        const { getByLabelText, getByTestId } = render(
            <RadioButton
                checked
                label='Option A'
                name='test-radiobutton'
                value='a'
                onChange={onChange}
            />
        );
        const wrapper = getByTestId('radiobutton-wrapper');
        const input = getByLabelText('Option A');

        expect(wrapper).toMatchSnapshot();
        expect(input).toHaveAttribute('checked');
    });

    it('should render a disabled radio button', () => {
        const { getByLabelText, getByTestId } = render(
            <RadioButton
                checked={true}
                disabled
                label='Option A'
                name='test-radiobutton'
                value='a'
                onChange={onChange}
            />
        );
        const wrapper = getByTestId('radiobutton-wrapper');
        const input = getByLabelText('Option A');

        expect(wrapper).toMatchSnapshot();
        expect(input).toHaveAttribute('checked');
        expect(input).toBeDisabled();
    });

    it('should handle id prop', () => {
        const { getByLabelText } = render(
            <RadioButton
                checked={false}
                id='custom-id'
                label='Option A'
                name='test-radiobutton'
                value='a'
                onChange={onChange}
            />
        );
        const input = getByLabelText('Option A');

        expect(input).toHaveAttribute('id', 'custom-id');
    });

    it('should render with additional className', () => {
        const { getByTestId } = render(
            <RadioButton
                checked={false}
                className='custom-class'
                label='Option A'
                name='test-radiobutton'
                value='a'
                onChange={onChange}
            />
        );
        const wrapper = getByTestId('radiobutton-wrapper');

        expect(wrapper).toHaveClass('denali-radiobutton');
        expect(wrapper).toHaveClass('custom-class');
    });

    it('should disabled animation', () => {
        const { getByTestId } = render(
            <RadioButton
                checked={false}
                label='Option A'
                name='test-radiobutton'
                noanim
                value='a'
                onChange={onChange}
            />
        );
        const wrapper = getByTestId('radiobutton-wrapper');

        expect(wrapper).toMatchSnapshot();
    });

    it('should handle onChange event', () => {
        const { getByLabelText } = render(
            <RadioButton
                checked={false}
                className='custom-class'
                label='Option A'
                name='test-radiobutton'
                value='a'
                onChange={onChange}
            />
        );
        const input = getByLabelText('Option A');

        fireEvent.click(input);

        expect(onChange).toHaveBeenCalled();
    });
});
