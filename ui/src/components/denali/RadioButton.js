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
import { rgba } from 'polished';
import { colors, cssFontStyles } from './styles/index';

const makeCssRadioButton = (props) => css`
    backface-visibility: hidden;
    box-sizing: border-box;
    display: inline-block;
    height: 16px;
    line-height: 16px;
    margin: 3px;
    outline: 0px;
    position: relative;
    vertical-align: bottom;
    label: radiobutton;

    & > input[type='radio'] {
        box-sizing: border-box;
        cursor: pointer;
        display: inline-block;
        position: absolute; /* Take it out of the documenet flow */
        top: 0;
        visibility: hidden; /* Hide it */
    }

    & > input[type='radio'] + label {
        box-sizing: border-box;
        cursor: pointer;
        ${cssFontStyles.default};
        height: 16px;
        line-height: 16px;
        padding: 0 10px 0 0;
        vertical-align: bottom;
        white-space: nowrap;
    }

    /* Outer circle */
    & > input[type='radio'] + label:before {
        background: ${colors.white};
        border: 2px solid ${rgba(colors.brand600, 0.5)};
        border-radius: 50%;
        box-sizing: border-box;
        content: '';
        cursor: pointer;
        display: inline-block;
        height: 16px;
        line-height: 16px;
        margin: 0px 3px -3px 0px;
        transition: ${!props.noanim ? 'all 0.25s ease-in' : undefined};
        width: 16px;
    }

    /* Circle hover */
    & > input[type='radio']:hover + label:before {
        border: 2px solid ${colors.brand600};
    }

    /* Circle focus */
    & > input[type='radio']:focus + label:before {
        border: 2px solid ${rgba(colors.brand600, 0.5)};
    }

    /* Circle checked */
    & > input[type='radio']:checked + label:before {
        border: 2px solid ${colors.brand600};
    }

    /* Disabled state label */
    & > input[type='radio']:disabled + label {
        color: ${colors.grey500};
        cursor: not-allowed;
    }

    /* Disabled circle */
    & > input[type='radio']:disabled + label:before {
        border: 2px solid ${colors.grey500};
        cursor: not-allowed;
    }

    /* Checked */
    & > input[type='radio']:checked + label:after {
        background-color: ${colors.brand600};
        border-radius: 50%;
        box-sizing: border-box;
        content: '';
        height: 8px;
        line-height: 8px;
        left: 4px;
        position: absolute;
        top: 4px;
        transition: ${!props.noanim ? 'all 0.2s ease-in' : undefined};
        width: 8px;
    }

    /* Disabled checked button */
    & > input[type='radio']:disabled:checked + label:after {
        color: ${colors.grey500};
        border: 2px solid ${colors.grey500};
        background-color: ${colors.grey500};
        cursor: not-allowed;
    }
`;

/**
 * Although `denali-react` exposes both `<RadioButtonGroup>` and `<RadioButton>`
 * as exports, under normal usage, you'll only want to use `<RadioButtonGroup>`
 * and let this library handle all the state changes between linked radio
 * buttons.
 */
class RadioButton extends React.PureComponent {
    getRadioButtonId = (id, name, value) => {
        if (id) {
            return id;
        }
        return `radiobutton-${name}-${id || value}`.replace(/[\s.#]/g, '_');
    };

    render() {
        const { className, id, innerRef, label, name, noanim, value, ...rest } =
            this.props;
        const cssProps = { noanim };
        const cssRadioButton = makeCssRadioButton(cssProps);
        const classes = cx(cssRadioButton, 'denali-radiobutton', className);
        const radioButtonId = this.getRadioButtonId(id, name, value);

        return (
            <div className={classes} data-testid='radiobutton-wrapper'>
                <input
                    {...rest}
                    ref={innerRef}
                    id={radioButtonId}
                    name={name}
                    value={value}
                />
                <label htmlFor={radioButtonId}>{label}</label>
            </div>
        );
    }
}

RadioButton.propTypes = {
    /** true = checked, false = unchecked */
    checked: PropTypes.bool.isRequired,
    /** Additonal class to apply to the outer div */
    className: PropTypes.string,
    /** ID of the radio button. If none is supplied, one will be generated */
    id: PropTypes.string,
    /** Forward React ref to the `<input>` element */
    innerRef: PropTypes.oneOfType([PropTypes.func, PropTypes.object]),
    /** Text to appear to the right of the checkbox */
    label: PropTypes.string,
    /** Name of the `<input>` element */
    name: PropTypes.string.isRequired,
    /** Disable animations / transitions */
    noanim: PropTypes.bool,
    /** @ignore */
    type: PropTypes.oneOf(['radio']),
    /** Value of the `<input>` element */
    value: PropTypes.oneOfType([
        PropTypes.bool,
        PropTypes.string,
        PropTypes.number,
    ]),
};

RadioButton.defaultProps = {
    noanim: false,
    type: 'radio',
};

export default RadioButton;
