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
import { css, cx } from '@emotion/css';
import { colors, cssFontSizes, cssFontWeights } from './styles/index';

const makeCssInputLabel = (props) => css`
    ${cssFontSizes.default};
    ${cssFontWeights.bold};
    color: ${colors.black};
    line-height: ${props.size === 'small' ? '28px' : '36px'};
    white-space: nowrap;
    label: input-label;
`;

/**
 * This component is used in conjunction with `<Input>`. You would use this like
 * you would a normal `<label>` element. Notably, use the `for` attribute to
 * associate a label with an input element (via `id`). For details, see:
 * https://www.w3.org/WAI/tutorials/forms/labels/#hiding-the-label-element
 */
const InputLabel = (props) => {
    const { className, size, ...rest } = props;
    const cssProps = { size };
    const cssInputLabel = makeCssInputLabel(cssProps);

    return (
        <label
            {...rest}
            className={cx(cssInputLabel, 'denali-input-label', className)}
        />
    );
};

InputLabel.propTypes = {
    /** Additonal class to apply to the outer div */
    className: PropTypes.string,
    /** Size (height) of input field */
    size: PropTypes.oneOf(['default', 'small']),
};

export default InputLabel;
