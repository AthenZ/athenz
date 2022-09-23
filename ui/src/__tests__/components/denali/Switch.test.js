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
import Switch from '../../../components/denali/Switch';

describe('Switch', () => {
    const ORIG_NODE_ENV = process.env.NODE_ENV;
    const onChange = jest.fn();

    afterEach(() => {
        onChange.mockClear();
        process.env.NODE_ENV = ORIG_NODE_ENV;
    });

    it('should render unchecked state', () => {
        const { getByTestId } = render(
            <Switch
                checked={false}
                label='test-label'
                name='test-switch'
                value='1'
                onChange={onChange}
            />
        );
        const wrapper = getByTestId('switch-wrapper');
        const inputNode = wrapper.querySelector('input');

        expect(wrapper).toMatchSnapshot();
        expect(inputNode).not.toHaveAttribute('checked');
        expect(inputNode).toHaveAttribute('id', 'switch-test-switch');
        expect(inputNode).not.toBeDisabled();
    });

    it('should render checked state', () => {
        const { getByTestId } = render(
            <Switch
                checked={true}
                label='test-label'
                name='test-switch'
                value='1'
                onChange={onChange}
            />
        );
        const wrapper = getByTestId('switch-wrapper');
        const inputNode = wrapper.querySelector('input');

        expect(wrapper).toMatchSnapshot();
        expect(inputNode).toHaveAttribute('checked');
        expect(inputNode).not.toBeDisabled();
    });

    it('should render disabled state', () => {
        const { getByTestId } = render(
            <Switch
                checked={false}
                disabled
                label='test-label'
                name='test-switch'
                value='1'
                onChange={onChange}
            />
        );
        const wrapper = getByTestId('switch-wrapper');
        const inputNode = wrapper.querySelector('input');

        expect(inputNode).toBeDisabled();
    });

    it('should handle id prop', () => {
        const { getByTestId } = render(
            <Switch
                checked={false}
                id='custom-id'
                label='test-label'
                name='test-switch'
                value='1'
                onChange={onChange}
            />
        );
        const wrapper = getByTestId('switch-wrapper');
        const inputNode = wrapper.querySelector('input');

        expect(inputNode).toHaveAttribute('id', 'custom-id');
    });

    it('should render with additional className', () => {
        const { getByTestId } = render(
            <Switch
                checked={false}
                className='custom-class'
                label='test-label'
                name='test-switch'
                value='1'
                onChange={onChange}
            />
        );
        const wrapper = getByTestId('switch-wrapper');

        expect(wrapper).toHaveClass('denali-switch');
        expect(wrapper).toHaveClass('custom-class');
    });

    it('should work with labelOn & labelOff', () => {
        const { queryByText, rerender } = render(
            <Switch
                checked={false}
                labelOn='test-label on'
                labelOff='test-label off'
                name='test-switch'
                value='1'
                onChange={onChange}
            />
        );

        expect(queryByText('test-label off')).not.toBeNull();
        expect(queryByText('test-label on')).toBeNull();

        rerender(
            <Switch
                checked={true}
                labelOn='test-label on'
                labelOff='test-label off'
                name='test-switch'
                value='1'
                onChange={onChange}
            />
        );

        expect(queryByText('test-label off')).toBeNull();
        expect(queryByText('test-label on')).not.toBeNull();
    });

    it('should warn on invalid labelOn & labelOff usage', () => {
        process.env.NODE_ENV = 'test';
        const consoleErrorSpy = jest
            .spyOn(console, 'error')
            .mockImplementation(() => {});

        render(
            <Switch
                checked
                name='test-switch1'
                labelOn='test-label on'
                value='1'
                onChange={onChange}
            />
        );
        render(
            <Switch
                checked
                name='test-switch2'
                labelOff='test-label off'
                value='1'
                onChange={onChange}
            />
        );

        expect(consoleErrorSpy).toHaveBeenCalledTimes(2);
    });

    it('should handle onChange event', () => {
        const { getByTestId } = render(
            <Switch
                checked={false}
                label='test-label'
                name='test-switch'
                value='1'
                onChange={onChange}
            />
        );
        const wrapper = getByTestId('switch-wrapper');
        const inputNode = wrapper.querySelector('input');

        fireEvent.click(inputNode);

        expect(onChange).toHaveBeenCalled();
    });
});
