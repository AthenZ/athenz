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
import _isBoolean from 'lodash/isBoolean';

const makeCssCheckbox = (props) => css`
    backface-visibility: hidden;
    box-sizing: border-box;
    display: inline-block;
    height: 16px;
    label: checkbox;
    line-height: 16px;
    margin: 3px;
    outline: 0;
    position: relative;
    vertical-align: middle;

    & > input[type='checkbox'] {
        box-sizing: border-box;
        cursor: pointer;
        display: inline-block;
        position: absolute; /* Take it out of the documenet flow */
        top: 0;
        visibility: hidden; /* Hide it */
    }

    & > input[type='checkbox'] + label {
        box-sizing: border-box;
        cursor: pointer;
        ${cssFontStyles.default};
        height: 16px;
        line-height: 16px;
        padding: 0 10px 0 0;
        vertical-align: bottom;
        white-space: nowrap;
    }

    /* Box */
    & > input[type='checkbox'] + label:before {
        background: ${colors.white};
        border: 2px solid ${rgba(colors.brand600, 0.5)};
        border-radius: 2px;
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

    /* Box hover */
    & > input[type='checkbox']:hover + label:before {
        border: 2px solid ${colors.brand600};
    }

    /* Box focus */
    & > input[type='checkbox']:focus + label:before {
        border: 2px solid ${rgba(colors.brand600, 0.5)};
    }

    /* Box checked */
    & > input[type='checkbox'][data-partial='true'] + label:before,
    & > input[type='checkbox']:checked + label:before {
        border: 2px solid ${colors.brand600};
    }

    /* Disabled state label */
    & > input[type='checkbox']:disabled + label {
        color: ${colors.grey500};
        cursor: not-allowed;
    }

    /* Disabled box */
    & > input[type='checkbox']:disabled + label:before {
        border: 2px solid ${colors.grey500};
    }

    /* Checkmark */
    &
        > input[type='checkbox']:checked:not([data-partial='true'])
        + label:before {
        background: ${colors.brand600};
    }

    /* Partial checked */
    & > input[type='checkbox'][data-partial='true'] + label:after {
        border: solid ${colors.brand600};
        border-width: 2px 0 0 0;
        box-sizing: border-box;
        content: '';
        cursor: pointer;
        height: 16px;
        line-height: 16px;
        left: 4px;
        opacity: 1;
        position: absolute;
        top: 7px;
        width: 8px;
    }

    /* Checked */
    &
        > input[type='checkbox']:checked:not([data-partial='true'])
        + label:after {
        border: solid ${colors.white};
        border-width: 0 2px 2px 0; /* creates the inverted "L" shape */
        box-sizing: border-box;
        content: '';
        cursor: pointer;
        display: block;
        height: 9px;
        line-height: 16px;
        left: 6px;
        opacity: 1;
        position: absolute;
        top: 3px;
        transform: rotate(45deg);
        width: 4.5px; /* the short bar of the mark is half as long as the long bar */
    }
`;

/**
 * Wrapper around `<input type="checkbox">`, with the ability to set partially
 * checked state. Note that you cannot click _into_ a partially checked state;
 * it must be set via props.
 */
class Checkbox extends React.PureComponent {
    getCheckedStateFromProps = (propChecked) => {
        if (_isBoolean(propChecked)) {
            return propChecked ? 1 : 0;
        }
        // It's numeric (PropTypes is type-checked, so only other possibility)
        return propChecked;
    };

    get checkboxId() {
        return (
            this.props.id || `checkbox-${this.props.name.replace(/\s/g, '_')}`
        );
    }

    render() {
        const { checked, className, innerRef, label, noanim, ...rest } =
            this.props;
        const checkedState = this.getCheckedStateFromProps(checked);
        const cssProps = { noanim };
        const cssCheckbox = makeCssCheckbox(cssProps);
        const classes = cx(cssCheckbox, 'denali-checkbox', className);

        return (
            <div className={classes} data-testid='checkbox-wrapper'>
                <input
                    {...rest}
                    checked={Boolean(checkedState !== 0)}
                    data-partial={checkedState === 2}
                    id={this.checkboxId}
                    ref={innerRef}
                />
                <label htmlFor={this.checkboxId}>{label}</label>
            </div>
        );
    }
}

Checkbox.propTypes = {
    /**
     * The checked property accepts either a boolean or a numeric (0-2) value. The
     * three possible states are: "unchecked" (`0` or `false`), "checked": (`1` or
     * `true`), and "partially checked" (`2`)
     */
    checked: PropTypes.oneOf([false, true, 0, 1, 2]),
    /** Additonal class to apply to the outer div */
    className: PropTypes.string,
    /** ID to attach to the input element */
    id: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
    /** Forward React ref to the `<input>` element */
    innerRef: PropTypes.oneOfType([PropTypes.func, PropTypes.object]),
    /** Text to appear to the right of the checkbox */
    label: PropTypes.string,
    /** Name of the `<input>` element */
    name: PropTypes.string.isRequired,
    /** Disable animations / transitions */
    noanim: PropTypes.bool,
    /** @ignore */
    type: PropTypes.oneOf(['checkbox']),
    /** Value of the `<input>` element */
    value: PropTypes.oneOfType([
        PropTypes.bool,
        PropTypes.string,
        PropTypes.number,
    ]),
};

Checkbox.defaultProps = {
    checked: 0,
    noanim: false,
    type: 'checkbox',
};

export default Checkbox;
