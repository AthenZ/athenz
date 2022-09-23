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
import Input from '../../../components/denali/Input';
import { colors } from '../../../components/denali/styles';
import Icon from '../../../components/denali/icons/Icon';

describe('Input', () => {
    const onChange = jest.fn();

    afterEach(() => onChange.mockClear());

    it('should render', () => {
        const { getByTestId } = render(
            <Input
                name='test-input'
                placeholder='test-placeholder'
                value=''
                onChange={onChange}
            />
        );
        const wrapper = getByTestId('input-wrapper');
        const inputNode = getByTestId('input-node');

        expect(wrapper).toMatchSnapshot();
        expect(inputNode).toHaveAttribute('placeholder', 'test-placeholder');
        expect(inputNode.value).toBe('');
        expect(wrapper).toHaveClass('animated');
    });

    it('should render a small input', () => {
        const { getByTestId } = render(
            <Input
                name='test-input'
                placeholder='test-placeholder'
                size='small'
                value=''
                onChange={onChange}
            />
        );
        const wrapper = getByTestId('input-wrapper');

        expect(wrapper).toMatchSnapshot();
    });

    it('should render an input with initial value', () => {
        const { getByTestId } = render(
            <Input
                name='test-input'
                placeholder='test-placeholder'
                value='a value'
                onChange={onChange}
            />
        );
        const inputNode = getByTestId('input-node');

        expect(inputNode.value).toBe('a value');
    });

    it('should render an input with pattern', () => {
        const { getByTestId } = render(
            <Input
                name='test-input'
                pattern='^\d*$'
                placeholder='Input only accepts numbers'
                value=''
                onChange={onChange}
            />
        );
        const inputNode = getByTestId('input-node');

        expect(inputNode.pattern).toBe('^\\d*$');
    });

    it('should render a focused input', () => {
        const { getByTestId } = render(
            <Input
                focused
                name='test-input'
                placeholder='Input only accepts numbers'
                value=''
                onChange={onChange}
            />
        );
        const wrapper = getByTestId('input-wrapper');
        const inputNode = getByTestId('input-node');

        expect(wrapper).toMatchSnapshot();
        expect(inputNode).toHaveClass('focused');
    });

    it('should render a disabled input', () => {
        const { getByTestId } = render(
            <Input
                disabled
                name='test-input'
                placeholder="Can't touch this"
                value=''
                onChange={onChange}
            />
        );
        const inputNode = getByTestId('input-node');

        expect(inputNode).toBeDisabled();
    });

    it('should render dark theme', () => {
        const { getByTestId } = render(
            <Input dark name='test-input' value='' onChange={onChange} />
        );
        const wrapper = getByTestId('input-wrapper');

        expect(wrapper).toMatchSnapshot();
    });

    it('should render disabled dark theme', () => {
        const { getByTestId } = render(
            <Input
                dark
                disabled
                name='test-input'
                value=''
                onChange={onChange}
            />
        );
        const wrapper = getByTestId('input-wrapper');
        const inputNode = getByTestId('input-node');

        expect(wrapper).toMatchSnapshot();
        expect(inputNode).toBeDisabled();
    });

    it('should render a fluid input', () => {
        const { getByTestId } = render(
            <Input fluid name='test-input' value='' onChange={onChange} />
        );
        const wrapper = getByTestId('input-wrapper');

        expect(wrapper).toMatchSnapshot();
        expect(wrapper).toHaveStyle(`width: 100%`);
    });

    it('should render an input with error', () => {
        const { getByTestId } = render(
            <Input
                error={true}
                message='An error has occurred'
                name='test-input'
                value=''
                onChange={onChange}
            />
        );
        const wrapper = getByTestId('input-wrapper');
        const message = getByTestId('message');

        expect(wrapper).toMatchSnapshot();
        expect(wrapper).toHaveClass('error');
    });

    it('should render an input with a label', () => {
        const label = <div>label</div>;
        const { getByTestId } = render(
            <Input
                label={label}
                name='test-input'
                value=''
                onChange={onChange}
            />
        );
        const wrapper = getByTestId('input-wrapper');

        expect(wrapper).toMatchSnapshot();
    });

    it('should render an input with an icon', () => {
        const { getByTestId } = render(
            <Input icon={Icon} name='test-input' value='' onChange={onChange} />
        );
        const wrapper = getByTestId('input-wrapper');

        expect(wrapper).toMatchSnapshot();
        expect(wrapper.querySelector('.input-icon')).not.toBeNull();
    });

    it('should render a small input with an icon', () => {
        const { getByTestId } = render(
            <Input
                icon={Icon}
                name='test-input'
                size='small'
                value=''
                onChange={onChange}
            />
        );
        const wrapper = getByTestId('input-wrapper');

        expect(wrapper).toMatchSnapshot();
        expect(wrapper.querySelector('.input-icon')).not.toBeNull();
    });

    it('should render icon with renderIcon function ', () => {
        const { getByTestId } = render(
            <Input
                renderIcon={({ sizePx }) => (
                    <Icon
                        icon={'search'}
                        color={colors.brand700}
                        size={sizePx}
                    />
                )}
                name='test-input'
                value=''
                onChange={onChange}
            />
        );
        const wrapper = getByTestId('input-wrapper');

        expect(wrapper).toMatchSnapshot();
        expect(wrapper.querySelector('.input-icon')).not.toBeNull();
    });

    it('should disable transitions', () => {
        const { getByTestId } = render(
            <Input
                name='test-input'
                noanim
                placeholder='test-placeholder'
                value=''
                onChange={onChange}
            />
        );
        const wrapper = getByTestId('input-wrapper');

        expect(wrapper).toMatchSnapshot();
        expect(wrapper).not.toHaveClass('animated');
    });

    it('should render with additional className', () => {
        const { getByTestId } = render(
            <Input
                className='custom-class'
                name='test-input'
                placeholder='Insert something here'
                value=''
                onChange={onChange}
            />
        );
        const wrapper = getByTestId('input-wrapper');

        expect(wrapper).toHaveClass('denali-input');
        expect(wrapper).toHaveClass('custom-class');
    });

    it('should handle change with onChange()', async () => {
        const onChange = jest.fn();
        const { getByTestId } = render(
            <Input name='test-input' value='old value' onChange={onChange} />
        );
        const inputNode = getByTestId('input-node');

        expect(onChange).toHaveBeenCalledTimes(0);
        fireEvent.change(inputNode, { target: { value: 'new value' } });

        expect(onChange).toHaveBeenCalledTimes(1);
        // TODO: Figure out why this doesn't work
        // Possibly relevant: https://github.com/kentcdodds/@testing-library/react/issues/175
        // expect(onChange).toHaveBeenCalledWith({ target: { value: 'new value' } })
    });
});
