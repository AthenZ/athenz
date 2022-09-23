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
import Tag from '../../../components/denali/Tag';

describe('Tag', () => {
    it('should render', () => {
        const { getByTestId } = render(<Tag>A tag</Tag>);
        const tag = getByTestId('tag');

        expect(tag).toMatchSnapshot();
    });

    it('should render a removable Tag', () => {
        const onClickRemove = jest.fn();
        const { getByTestId } = render(
            <Tag onClickRemove={onClickRemove}>A tag</Tag>
        );
        const tag = getByTestId('tag');

        expect(tag).toMatchSnapshot();
        // fireEvent.click(tag.querySelector('.remove-button'));
        // expect(onClickRemove).toHaveBeenCalledTimes(1);
    });

    it('should render a selectable Tag', () => {
        const onClick = jest.fn();
        const { getByTestId } = render(<Tag onClick={onClick}>A tag</Tag>);
        const tag = getByTestId('tag');

        expect(tag).toMatchSnapshot();
        fireEvent.click(tag);
        expect(onClick).toHaveBeenCalledTimes(1);
    });

    it('should render a disabled Tag', () => {
        const { getByTestId } = render(<Tag disabled>A tag</Tag>);
        expect(getByTestId('tag')).toMatchSnapshot();
    });

    it('should render a small Tag', () => {
        const onClickRemove = jest.fn();
        const { getByTestId } = render(
            <Tag small onClickRemove={onClickRemove}>
                A tag
            </Tag>
        );

        expect(getByTestId('tag')).toMatchSnapshot();
    });

    it('should render with an additional class name', () => {
        const { getByTestId } = render(
            <Tag className='custom-class'>A tag</Tag>
        );
        const tag = getByTestId('tag');

        expect(tag).toHaveClass('denali-tag');
        expect(tag).toHaveClass('custom-class');
    });

    it('should disable transitions', () => {
        const { getByTestId } = render(<Tag noanim>A tag</Tag>);
        const tag = getByTestId('tag');

        expect(tag).toMatchSnapshot();
    });

    it('should warn on invalid use of onClick & onClickRemove', () => {
        const onClick = jest.fn();
        const onClickRemove = jest.fn();
        const consoleErrorSpy = jest
            .spyOn(console, 'error')
            .mockImplementation(() => {});

        render(
            <Tag onClick={onClick} onClickRemove={onClickRemove}>
                A tag
            </Tag>
        );

        expect(consoleErrorSpy).toHaveBeenCalledTimes(1);
    });
});
