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
import Icon from '../../../../components/denali/icons/Icon';
import { render } from '@testing-library/react';

describe('Icon', () => {
    it('should render default icon', () => {
        let icon = <Icon />;
        expect(icon.props.icon).toEqual('x');
        expect(icon.props.size).toEqual('1em');
        expect(icon.props.verticalAlign).toEqual('text-bottom');
    });

    it('should render an icon with values provided', () => {
        let icon = <Icon icon='accountkey' size='1em' color='icons-white' />;
        expect(icon.props.icon).toEqual('accountkey');
        expect(icon.props.size).toEqual('1em');
        expect(icon.props.color).toEqual('icons-white');
    });

    it('should render default icon with svg', () => {
        const { getByTestId } = render(<Icon />);
        const icon = getByTestId('icon');
        expect(icon).toMatchSnapshot();
    });
});
