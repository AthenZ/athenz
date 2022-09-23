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

// NOTE: We probably don't need a wrapper div, but keep one in case
// we have something like a message div
const makeCssTextArea = (props) => css`
    ${cssFontStyles.default};
    box-sizing: border-box;
    display: inline-flex;
    flex-flow: column nowrap;
    position: relative;
    width: ${props.fluid ? '100%' : props.width || '250px'};
    label: textarea;

    & > textarea {
        appearance: none;
        background: ${props.dark
            ? rgba(colors.grey300, 0.1)
            : rgba(colors.brand700, 0.05)};
        border-top: 2px solid transparent;
        border-bottom: 2px solid ${props.error ? colors.red600 : 'transparent'};
        border-right: transparent;
        border-left: transparent;
        border-radius: 2px;
        box-shadow: none;
        box-sizing: border-box;
        color: ${props.dark ? colors.white : colors.grey800};
        flex: 1 0 auto;
        font: inherit;
        height: ${props.height};
        line-height: 1.5;
        margin: 0;
        outline: none;
        padding: 0.25em 0.75rem;
        text-align: left;
        transition: ${!props.noanim
            ? 'background-color 0.2s ease-in-out, color 0.2s ease-in-out, border 0.2s ease-in-out'
            : undefined};
        width: auto;
    }

    /* Placeholder */
    & > textarea::placeholder {
        color: ${props.dark
            ? rgba(colors.white, 0.2)
            : rgba(colors.grey800, 0.6)};
    }

    /* Focused / Active */
    & > textarea:active,
    & > textarea:focus {
        background: ${props.dark
            ? rgba(colors.grey300, 0.1)
            : rgba(colors.brand700, 0.05)};
        border-bottom: 2px solid ${colors.brand700};
        color: ${props.dark ? colors.white : colors.grey800};
    }

    /* Invalid */
    & > textarea:invalid {
        background: ${rgba(colors.brand700, 0.05)};
        border-bottom: 2px solid ${colors.red600};
        color: ${colors.grey800};
    }

    /* Disabled */
    & > textarea[disabled] {
        background: ${props.dark
            ? rgba(colors.white, 0.1)
            : rgba(colors.grey800, 0.05)};
        border-bottom: 2px solid
            ${props.dark
                ? rgba(colors.white, 0.05)
                : rgba(colors.grey800, 0.05)};
        color: ${props.dark
            ? rgba(colors.white, 0.1)
            : rgba(colors.grey800, 0.25)};
        cursor: not-allowed;
    }

    & .message {
        ${cssFontSizes.subtitle};
        color: ${props.error ? colors.red600 : colors.black};
        left: 0;
        line-height: 1.8;
        position: absolute;
        top: 2.571rem;
    }
`;

/**
 * Styled wrapper around `<textarea>`
 *
 * Aside from custom props below, all standard `<textarea>` props are supported.
 * See: https://developer.mozilla.org/en-US/docs/Web/HTML/Element/textarea
 *
 * There are two key differences between using HTML's `<textarea>` and this
 * `<TextArea>` component:
 *
 * 1. `<TextArea>` uses the `value` prop instead of `children`, which is
 * inline with React practices:
 * https://reactjs.org/docs/forms.html#the-textarea-tag
 * 2. For read-only, use `readOnly` instead of `readonly` (note the camel case)
 */
class TextArea extends React.PureComponent {
    render() {
        // Pull out all the component-specific props. This allows the developer to
        // pass in additional `<textarea>` attributes without specifically having to
        // define them within this component.
        const {
            className,
            dark,
            error,
            fluid,
            height,
            innerRef,
            noanim,
            width,
            ...rest
        } = this.props;

        const cssProps = { dark, error, fluid, height, noanim, width };
        const cssTextArea = makeCssTextArea(cssProps);

        return (
            <div
                className={cx(cssTextArea, 'denali-textarea', className)}
                data-testid='textarea-wrapper'
            >
                <textarea {...rest} ref={innerRef} data-testid='textarea' />
            </div>
        );
    }
}

TextArea.propTypes = {
    /** Additonal class to apply to the outer div */
    className: PropTypes.string,
    /** Dark theme */
    dark: PropTypes.bool,
    /** Display rrror state */
    error: PropTypes.bool,
    /** TextArea fills entire width of parent container */
    fluid: PropTypes.bool,
    /** Height of the textarea (alternative to `rows` attribute) */
    height: PropTypes.string,
    /** Forward React ref to the `<textarea>` element */
    innerRef: PropTypes.oneOfType([PropTypes.func, PropTypes.object]),
    /** Disable animations / transitions */
    noanim: PropTypes.bool,
    /** Content of the textarea. This is the single source of truth */
    value: PropTypes.string,
    /** Width of the textarea (alternative to `cols` attribute) */
    width: PropTypes.string,
};

TextArea.defaultProps = {
    dark: false,
    error: false,
    fluid: false,
    height: 'auto',
    noanim: false,
};

export default TextArea;
