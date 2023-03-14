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
import { colors } from './styles/colors';
import { cssFontStyles } from './styles/fonts';

const makeCssSwitch = (props) => css`
    align-items: center;
    backface-visibility: hidden;
    box-sizing: border-box;
    display: inline-flex;
    height: 18px;
    outline: 0;
    position: relative;
    label: switch;

    & > input[type='checkbox'] {
        box-sizing: border-box;
        cursor: pointer;
        position: absolute; /* Take it out of the document flow */
        top: 0;
        visibility: hidden; /* Hide it */
    }

    & > input[type='checkbox'] + label {
        box-sizing: border-box;
        cursor: pointer;
        ${cssFontStyles.default};
        height: 18px;
        line-height: 18px;
        white-space: nowrap;

        & .label-content {
            display: inline-flex;
            margin-left: 6px;

            /* Firefox Quantum's text is off by 1px compared to Chrome/Safari,
       * so hack it to align with the other browsers. */
            @-moz-document url-prefix() {
                margin-top: 1px;
            }
        }
    }

    /* Line behind circle */
    & > input[type='checkbox'] + label:before {
        background: ${colors.grey500};
        border-radius: 9px;
        box-sizing: border-box;
        content: '';
        cursor: pointer;
        display: inline-block;
        height: 4px;
        line-height: 16px;
        margin: 7px 0 0 0;
        transition: all 0.25s;
        vertical-align: top;
        width: 34px;
    }

    /* Circle */
    & > input[type='checkbox'] + label::after {
        background-color: ${colors.white};
        border: 2px solid ${rgba(colors.brand600, 0.5)};
        border-radius: 50%;
        box-sizing: border-box;
        content: ' ';
        cursor: pointer;
        display: block;
        height: 18px;
        left: 0;
        position: absolute;
        transition: ${!props.noanim ? 'all 0.25s ease' : undefined};
        top: 0; /* Slight adjustment to due vertical-align: text-bottom */
        width: 18px;
    }

    /* Checked line behind circle */
    & > input[type='checkbox']:checked + label::before {
        background-color: ${rgba(colors.statusSuccess, 0.45)};
    }

    /* Checked circle */
    & > input[type='checkbox']:checked + label::after {
        background-color: ${colors.statusSuccess};
        border-color: ${colors.statusSuccess};
        left: 16px;
    }

    /* Disabled label */
    & > input[type='checkbox']:disabled + label {
        color: ${colors.grey600};
        cursor: not-allowed;
    }

    /* Disabled line behind circle */
    & > input[type='checkbox']:disabled + label::before {
        background-color: ${colors.grey400};
        cursor: not-allowed;
    }

    /* Disabled (unchecked) circle */
    & > input[type='checkbox']:disabled + label::after {
        border-color: ${colors.grey500};
        cursor: not-allowed;
    }

    /* Disabled checked circle */
    & > input[type='checkbox']:checked:disabled + label::after {
        background: ${colors.grey500};
    }
`;

/**
 * A wrapper around `<input type="checkbox>`, similar to `<Checkbox>`, except
 * this component is styled as a toggle switch instead.
 */
class Switch extends React.PureComponent {
    get switchId() {
        return this.props.id || `switch-${this.props.name.replace(/\s/g, '_')}`;
    }

    get label() {
        if (this.props.checked && this.props.labelOn) {
            return this.props.labelOn;
        } else if (!this.props.checked && this.props.labelOff) {
            return this.props.labelOff;
        }
        return this.props.label;
    }

    render() {
        /* eslint-disable no-unused-vars */
        const {
            className,
            innerRef,
            label,
            labelOn,
            labelOff,
            noanim,
            ...rest
        } = this.props;
        const cssProps = { noanim };
        const cssSwitch = makeCssSwitch(cssProps);

        const classes = cx(cssSwitch, 'denali-switch', className);

        return (
            <div className={classes} data-testid='switch-wrapper'>
                <input
                    {...rest}
                    id={this.switchId}
                    ref={innerRef}
                    data-testid={
                        this.props.name
                            ? this.props.name + '-switch-input'
                            : 'switch-input'
                    }
                />
                <label htmlFor={this.switchId}>
                    {this.label && (
                        <div className='label-content'>{this.label}</div>
                    )}
                </label>
            </div>
        );
    }
}

Switch.propTypes = {
    /** true = checked, false = unchecked */
    checked: PropTypes.bool.isRequired,
    /** Additonal class to apply to the outer div */
    className: PropTypes.string,
    /** ID to attach to the `<input>` element */
    id: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
    /** Forward React ref to the `<input>` element */
    innerRef: PropTypes.oneOfType([PropTypes.func, PropTypes.object]),
    /** Text to appear to the right of the checkbox */
    label: PropTypes.string,
    /** Used in conjunction with `labelOn` for seperate on/off labels (overrides `label`) */
    labelOff: PropTypes.string,
    /** Used in conjunction with `labelOff` for seperate on/off labels (overrides `label`) */
    labelOn: PropTypes.string,
    /**
     * Validator to ensure `labelOn` & `labelOff` are both defined or both undefined
     * @ignore
     */
    labelOnAndOff: function (props, propName, componentName) {
        if (props.labelOff && !props.labelOn) {
            return new Error(
                'Prop `labelOff` requires `labelOn` to also be defined in `' +
                    componentName +
                    '`. Validation failed.'
            );
        }
        if (props.labelOn && !props.labelOff) {
            return new Error(
                'Prop `labelOn` requires `labelOff` to also be defined in `' +
                    componentName +
                    '`. Validation failed.'
            );
        }
    },
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

Switch.defaultProps = {
    noanim: false,
    type: 'checkbox',
};

export default Switch;
