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
import { colors, cssFontSizes, cssFontStyles } from './styles/index';

const makeInputBaseClass = (props) => css`
    box-sizing: border-box;
    display: inline-flex;
    flex-flow: row nowrap;
    ${cssFontStyles.default};
    position: relative;
    width: ${props.fluid ? '100%' : '250px'};
    label: input;
    & input {
        appearance: none;
        background: ${rgba(colors.brand700, 0.05)};
        border-top: 2px solid transparent;
        border-bottom: 2px solid transparent;
        border-right: transparent;
        border-left: transparent;
        border-radius: 2px;
        box-shadow: none;
        box-sizing: border-box;
        color: ${colors.grey800};
        flex: 1 0 auto;
        font: inherit;
        height: ${props.size === 'small' ? '28px' : '36px'};
        margin: 0;
        outline: none;
        padding: 0 1rem;
        text-align: left;
        width: 100%;
    }
    &.animated input {
        transition: background-color 0.2s ease-in-out, color 0.2s ease-in-out,
            border 0.2s ease-in-out;
    }
    /* Placeholder */
    & input::placeholder {
        color: ${rgba(colors.grey800, 0.6)};
    }
    /* Focused / Active */
    & input.focused,
    & input:active,
    & input:focus {
        background: ${rgba(colors.brand700, 0.05)};
        border-bottom: 2px solid ${colors.brand700};
        color: ${colors.grey800};
    }
    /* Invalid */
    & input:invalid {
        background: ${rgba(colors.brand700, 0.05)};
        border-bottom: 2px solid ${colors.red600};
        color: ${colors.grey800};
    }
    & .message {
        ${cssFontSizes.subtitle};
        left: 0;
        line-height: 1.8;
        position: absolute;
        top: 2.571rem;
    }
    &.error input,
    &.error input.focused,
    &.error input:active,
    &.error input:focus {
        border-bottom: 2px solid ${colors.red600};
    }
    &.error .message {
        color: ${colors.red600};
    }
`;

const darkCss = css`
    & input {
        background: ${rgba(colors.grey300, 0.1)};
        color: ${colors.white};
    }
    & input::placeholder {
        color: ${rgba(colors.white, 0.6)};
    }
    & input.focused,
    & input:active,
    & input:focus {
        background: ${rgba(colors.grey300, 0.1)};
        border-bottom: 2px solid ${colors.brand700};
        color: ${colors.white};
    }
`;

const darkDisabledCss = css`
    & input[disabled] {
        background: ${rgba(colors.white, 0.1)};
        border-bottom: 2px solid ${rgba(colors.white, 0.05)};
        color: ${rgba(colors.white, 0.1)};
        cursor: not-allowed;
    }
    & input::placeholder {
        color: ${rgba(colors.white, 0.2)};
    }
`;

const disabledCss = css`
    & input[disabled] {
        background: ${rgba(colors.grey800, 0.05)};
        border-bottom: 2px solid ${rgba(colors.grey800, 0.05)};
        color: ${rgba(colors.grey800, 0.25)};
        cursor: not-allowed;
    }
`;

const makeIconClass = (props) => css`
    & input {
        padding-right: ${props.size === 'small' ? '28px' : '36px'};
    }
    & .input-icon {
        align-items: center;
        display: flex;
        height: ${props.size === 'small' ? '28px' : '36px'};
        position: absolute;
        right: 6px;
    }
`;

const labeledCss = css`
    & input {
        border-top-right-radius: 0;
        border-bottom-right-radius: 0;
    }
    & .input-label {
        align-items: center;
        background: linear-gradient(
            45deg,
            ${colors.brand600} 0%,
            ${colors.brand500} 100%
        );
        border-radius: 0 2px 2px 0;
        color: ${colors.white};
        display: flex;
        justify-content: center;
        padding: 0 10px;
        white-space: nowrap;
    }
`;

/**
 * Styled wrapper around `<input>` of the text field variety, providing extra
 * functionality such as labels and icons.
 */
class Input extends React.PureComponent {
    renderIcon({ icon: Icon, renderIcon }, size) {
        const sizePx = size === 'small' ? '20px' : '24px';
        if (renderIcon) {
            return <div className='input-icon'>{renderIcon({ sizePx })}</div>;
        } else if (Icon) {
            return (
                <div className='input-icon'>
                    <Icon size={sizePx} />
                </div>
            );
        }
    }
    render() {
        // Pull out all the component-specific props. This allows the developer to
        // pass in additional `<input>` properties (such as ARIA) without
        // specifically having to define them within this component.
        const {
            className,
            dark,
            error,
            fluid,
            focused,
            icon,
            innerRef,
            label,
            message,
            noanim,
            renderIcon,
            size,
            ...rest
        } = this.props;

        const cssProps = {
            dark,
            error,
            fluid,
            focused,
            icon,
            label,
            message,
            renderIcon,
            size,
        };

        let inputWrapperClass = makeInputBaseClass(cssProps);

        if (dark && rest.disabled) {
            inputWrapperClass = css`
                ${inputWrapperClass};
                ${darkDisabledCss};
            `;
        } else if (dark) {
            inputWrapperClass = css`
                ${inputWrapperClass};
                ${darkCss};
            `;
        } else if (rest.disabled) {
            inputWrapperClass = css`
                ${inputWrapperClass};
                ${disabledCss};
            `;
        }
        if (label) {
            inputWrapperClass = css`
                ${inputWrapperClass};
                ${labeledCss};
            `;
        }
        if (icon || renderIcon) {
            inputWrapperClass = css`
                ${inputWrapperClass};
                ${makeIconClass(this.props)};
            `;
        }
        return (
            <div
                className={cx(
                    inputWrapperClass,
                    'denali-input',
                    {
                        error,
                        animated: !noanim,
                    },
                    className
                )}
                data-testid='input-wrapper'
            >
                <input
                    {...rest}
                    className={focused ? 'focused' : undefined}
                    ref={innerRef}
                    data-testid='input-node'
                    // disabling autocomplete at the root
                    // can be exported as props if needed
                    autoComplete={'off'}
                />
                {this.renderIcon({ icon, renderIcon }, size)}
                {label && <div className='input-label'>{label}</div>}
                <div className='message' data-testid='message'>
                    {message}
                </div>
            </div>
        );
    }
}

Input.propTypes = {
    /** Additonal class to apply to the outer div */
    className: PropTypes.string,
    /** Dark theme */
    dark: PropTypes.bool,
    /** Force input into error state (similar to typing invalid input) */
    error: PropTypes.bool,
    /** Input fills entire width of parent container */
    fluid: PropTypes.bool,
    /** Manually set focused state */
    focused: PropTypes.bool,
    /**
     * Icon to attach inside of the input field. This should be an already
     * imported icon from `denali-react-icons` */
    icon: PropTypes.func,
    /**
     * Pass a React ref to the input field
     */
    innerRef: PropTypes.oneOfType([PropTypes.func, PropTypes.object]),
    /** Attach a label to the right of the input field */
    label: PropTypes.any,
    /** Display a message under the input field */
    message: PropTypes.string,
    /** Disable animations / transitions */
    noanim: PropTypes.bool,
    /**
     * More flexible version of the `icon` prop, where you define exactly what
     * gets rendered. The render prop function receives `sizePx` prop (eg. '34px')
     * for you to use.
     */
    renderIcon: PropTypes.func,
    /** Size (height) of input field */
    size: PropTypes.oneOf(['default', 'small']),
    /** Content of the textarea. This is the single source of truth */
    value: PropTypes.string,
};

// TODO: Add support for input sizes
// input: 28, 30, 36

Input.defaultProps = {
    dark: false,
    error: false,
    fluid: false,
    focused: false,
    noanim: false,
    size: 'default',
};

export default Input;
