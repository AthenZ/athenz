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
import TextArea from '../../../components/denali/TextArea';

describe('TextArea', () => {
    const onChange = jest.fn();

    afterEach(() => onChange.mockClear());

    it('should render', () => {
        const { getByTestId } = render(
            <TextArea
                name='test1'
                placeholder='Insert something here'
                value=''
                onChange={onChange}
            />
        );
        const wrapper = getByTestId('textarea-wrapper');
        const textarea = getByTestId('textarea');

        expect(wrapper).toMatchSnapshot();
        expect(textarea.value).toBe('');
    });

    it('should handle width / height', () => {
        const { getByTestId } = render(
            <TextArea
                height='100px'
                name='test2a'
                value=''
                width='400px'
                onChange={onChange}
            />
        );
        const wrapper = getByTestId('textarea-wrapper');
        const textarea = getByTestId('textarea');

        expect(wrapper).toMatchSnapshot();
        expect(wrapper).toHaveStyle(`width: 400px`);
        expect(textarea).toHaveStyle(`height: 100px`);
    });

    it('should handle fluid', () => {
        const { getByTestId } = render(
            <TextArea name='test2b' value='' fluid onChange={onChange} />
        );
        const wrapper = getByTestId('textarea-wrapper');

        expect(wrapper).toHaveStyle(`width: 100%`);
    });

    it('should render a disabled TextArea', () => {
        const { getByTestId } = render(
            <TextArea
                disabled
                name='test4'
                placeholder="Can't touch this"
                value=''
                onChange={onChange}
            />
        );
        const textarea = getByTestId('textarea');

        expect(textarea).toHaveAttribute('disabled');
    });

    it('should render dark theme', () => {
        const { getByTestId } = render(
            <TextArea dark name='test5a' value='' onChange={onChange} />
        );
        const wrapper = getByTestId('textarea-wrapper');

        expect(wrapper).toMatchSnapshot();
    });

    it('should render disabled dark theme', () => {
        const { getByTestId } = render(
            <TextArea
                dark
                disabled
                name='test5b'
                value=''
                onChange={onChange}
            />
        );
        const wrapper = getByTestId('textarea-wrapper');
        const textarea = getByTestId('textarea');

        expect(wrapper).toMatchSnapshot();
        expect(textarea).toHaveAttribute('disabled');
    });

    it('should disable transitions', () => {
        const { getByTestId } = render(
            <TextArea
                name='test6'
                noanim
                placeholder='Insert something here'
                value=''
                onChange={onChange}
            />
        );
        const wrapper = getByTestId('textarea-wrapper');

        expect(wrapper).toMatchSnapshot();
    });

    it('should render error state', () => {
        const { getByTestId } = render(
            <TextArea
                error
                name='test7'
                value='This is an error'
                onChange={onChange}
            />
        );
        const wrapper = getByTestId('textarea-wrapper');

        expect(wrapper).toMatchSnapshot();
    });

    it('should render with additional className', () => {
        const { getByTestId } = render(
            <TextArea
                className='custom-class'
                name='test8'
                placeholder='Insert something here'
                value=''
                onChange={onChange}
            />
        );
        const wrapper = getByTestId('textarea-wrapper');

        expect(wrapper).toHaveClass('denali-textarea');
        expect(wrapper).toHaveClass('custom-class');
    });

    it('should handle change with onChange()', () => {
        const { getByTestId } = render(
            <TextArea name='test9' value='old value' onChange={onChange} />
        );
        const textarea = getByTestId('textarea');

        fireEvent.change(textarea, { target: { value: 'new value' } });

        expect(onChange).toHaveBeenCalled();
    });
});
