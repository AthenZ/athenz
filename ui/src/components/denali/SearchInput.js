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
import PropTypes from 'prop-types';
import Input from './Input';
import Icon from './icons/Icon';
import { colors } from './styles/colors';

/**
 * This component is just a thin wrapper around
 * [`<Input>`](/#!/Input) that is styled for a search input field.
 */
// NOTE: This has to be a React class so refs work.
class SearchInput extends React.Component {
    render() {
        return (
            <Input
                {...this.props}
                renderIcon={({ sizePx }) => (
                    <Icon
                        icon={'search'}
                        color={colors.brand700}
                        size={sizePx}
                    />
                )}
            />
        );
    }
}

SearchInput.propTypes = {
    /** Additonal class to apply to the outer div */
    className: PropTypes.string,
    /** Dark theme */
    dark: PropTypes.bool,
    /** Force input into error state (similar to typing invalid input) */
    error: PropTypes.bool,
    /** Input fills entire width of parent container */
    fluid: PropTypes.bool,
    /** Attach a label to the right of the input field */
    label: PropTypes.any,
    /** Display a message under the input field */
    message: PropTypes.string,
    /** Placeholder (default: "Search") */
    placeholder: PropTypes.string,
    /** Disable animations / transitions */
    noanim: PropTypes.bool,
    /** Size (height) of input field */
    size: PropTypes.oneOf(['default', 'small']),
    /** Content of the textarea. This is the single source of truth */
    value: PropTypes.string,
};

SearchInput.defaultProps = {
    dark: false,
    disabled: false,
    error: false,
    fluid: false,
    noanim: false,
    placeholder: 'Search',
};

export default SearchInput;
