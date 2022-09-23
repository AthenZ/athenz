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
import Button from '../../../components/denali/Button';

describe('Button', () => {
    it('should render a button', () => {
        const { getByText } = render(<Button>A button</Button>);
        const button = getByText('A button');

        expect(button).toMatchSnapshot();
    });

    it('should render an active button', () => {
        const { getByText } = render(<Button active>A button</Button>);
        const button = getByText('A button');

        expect(button).toMatchSnapshot();
    });

    it('should render a disabled button', () => {
        const { getByText } = render(<Button disabled>A button</Button>);
        const button = getByText('A button');

        expect(button).toMatchSnapshot();
    });

    it('should render a secondary button', () => {
        const { getByText } = render(<Button secondary>A button</Button>);
        const button = getByText('A button');

        expect(button).toMatchSnapshot();
    });

    it('should render a secondary active button', () => {
        const { getByText } = render(
            <Button secondary active>
                A button
            </Button>
        );
        const button = getByText('A button');

        expect(button).toMatchSnapshot();
    });

    it('should render a secondary disable button', () => {
        const { getByText } = render(
            <Button secondary disabled>
                A button
            </Button>
        );
        const button = getByText('A button');

        expect(button).toMatchSnapshot();
    });

    it('should render a danger button', () => {
        const { getByText } = render(<Button danger>A button</Button>);
        const button = getByText('A button');

        expect(button).toMatchSnapshot();
    });

    it('should render a large button', () => {
        const { getByText } = render(<Button size='large'>A button</Button>);
        const button = getByText('A button');

        expect(button).toMatchSnapshot();
    });

    it('should render a small button', () => {
        const { getByText } = render(<Button size='small'>A button</Button>);
        const button = getByText('A button');

        expect(button).toMatchSnapshot();
    });

    it('should render a dark active button', () => {
        const { getByText } = render(
            <Button dark active>
                A button
            </Button>
        );
        const button = getByText('A button');

        expect(button).toMatchSnapshot();
    });

    it('should render a dark disable button', () => {
        const { getByText } = render(
            <Button dark disabled>
                A button
            </Button>
        );
        const button = getByText('A button');

        expect(button).toMatchSnapshot();
    });

    it('should render a dark secondary button', () => {
        const { getByText } = render(
            <Button dark secondary>
                A button
            </Button>
        );
        const button = getByText('A button');

        expect(button).toMatchSnapshot();
    });

    it('should render a dark secondary active button', () => {
        const { getByText } = render(
            <Button dark secondary active>
                A button
            </Button>
        );
        const button = getByText('A button');

        expect(button).toMatchSnapshot();
    });

    it('should render a dark secondary disable button', () => {
        const { getByText } = render(
            <Button dark secondary disabled>
                A button
            </Button>
        );
        const button = getByText('A button');

        expect(button).toMatchSnapshot();
    });

    it('should render a dark danger button', () => {
        const { getByText } = render(
            <Button dark danger>
                A button
            </Button>
        );
        const button = getByText('A button');

        expect(button).toMatchSnapshot();
    });

    it('should render a dark large button', () => {
        const { getByText } = render(
            <Button dark size='large'>
                A button
            </Button>
        );
        const button = getByText('A button');

        expect(button).toMatchSnapshot();
    });

    it('should render a dark small button', () => {
        const { getByText } = render(
            <Button dark size='small'>
                A button
            </Button>
        );
        const button = getByText('A button');

        expect(button).toMatchSnapshot();
    });

    it('should disable animations', () => {
        const { getByText } = render(
            <Button secondary noanim>
                A button
            </Button>
        );
        const button = getByText('A button');

        expect(button).toMatchSnapshot();
    });

    it('should render with an additional class name', () => {
        const { getByText } = render(
            <Button className='custom-class'>A button</Button>
        );
        const button = getByText('A button');

        expect(button).toHaveClass('denali-button');
        expect(button).toHaveClass('custom-class');
    });

    it('should handle onClick event', () => {
        const onClick = jest.fn();
        const { getByText } = render(
            <Button onClick={onClick}>A button</Button>
        );
        const button = getByText('A button');

        fireEvent.click(button);
        expect(onClick).toHaveBeenCalled();
    });
});
