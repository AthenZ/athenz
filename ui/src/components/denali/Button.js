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
import { cx, css } from '@emotion/css';
import { rgba } from 'polished';
import { colors } from './styles/colors';
import { cssFontFamilies, cssFontWeights } from './styles/fonts';

// NOTE: Psuedo class priority:
// Link Visited Hover Focus Active
// "Lord Vader Hates Furry Animals"

const buttonBase = (props) => css`
    border: none;
    border-radius: 2px;
    box-shadow: 0 0 0 1px transparent inset, 0 0 0 0 ${colors.grey500} inset;
    box-sizing: border-box;
    cursor: pointer;
    display: inline-block;
    ${cssFontFamilies.default};
    ${cssFontWeights.normal};
    font-size: ${props.size === 'large'
        ? '18px'
        : props.size === 'regular'
        ? '14px'
        : '12px'};
    line-height: 1;
    margin: 5px;
    min-width: ${props.size === 'small' ? '70px' : undefined};
    outline: 0;
    padding: ${props.size === 'large'
        ? '12px 28px'
        : props.size === 'regular'
        ? '10px 24px'
        : '8px 18px'};
    text-align: center;
    text-shadow: none;
    text-transform: none;
    transition: ${!props.noanim ? 'all 0.2s ease-in' : undefined};
    vertical-align: baseline;
    white-space: nowrap;
    label: button;
    &:first-of-type {
        margin-left: 0;
    }
    &:disabled {
        background: ${props.dark
            ? rgba(colors.white, 0.1)
            : rgba(colors.grey800, 0.1)};
        color: ${props.dark
            ? rgba(colors.white, 0.2)
            : rgba(colors.grey800, 0.2)};
        cursor: not-allowed;
    }
`;

const buttonVariants = {
    primary: (props) => css`
        background: linear-gradient(
            to right,
            ${props.active ? colors.brand700 : colors.brand600},
            ${props.active ? colors.brand800 : colors.brand700}
        );
        color: ${colors.white};
        &:hover:not(:disabled) {
            background: linear-gradient(
                to right,
                ${colors.brand700},
                ${colors.brand800}
            );
        }
    `,
    secondary: (props) => css`
        background: ${props.dark
            ? props.active
                ? `linear-gradient(to right, ${rgba(
                      colors.brand700,
                      0.3
                  )}, ${rgba(colors.brand800, 0.3)})`
                : 'transparent'
            : props.active
            ? colors.brand200
            : 'transparent'};
        box-shadow: 0 0 0 1px ${colors.brand600} inset;
        color: ${props.dark ? colors.white : colors.brand600};
        &:disabled {
            box-shadow: ${props.dark
                ? `0 0 0 1px ${rgba(colors.white, 0.2)} inset`
                : `0 0 0 1px ${rgba(colors.grey800, 0.1)} inset`};
        }
        &:hover:not(:disabled) {
            background: ${props.dark
                ? `linear-gradient(to right, ${rgba(
                      colors.brand700,
                      0.3
                  )}, ${rgba(colors.brand800, 0.3)})`
                : colors.brand200};
        }
    `,
    danger: () => css`
        background: ${colors.red500};
        color: ${colors.white};
        &:hover:not(:disabled) {
            background: ${colors.red600};
        }
    `,
};

class Button extends React.PureComponent {
    render() {
        const {
            active,
            className,
            danger,
            dark,
            noanim,
            secondary,
            size,
            ...rest
        } = this.props;

        const cssProps = { active, dark, noanim, size };

        const makeCssButton = (props) => css`
            ${buttonBase(props)};
            ${(danger
                ? buttonVariants.danger
                : secondary
                ? buttonVariants.secondary
                : buttonVariants.primary)(props)};
        `;
        const cssButton = makeCssButton(cssProps);

        const classes = cx(cssButton, 'denali-button', className);

        return <button className={classes} {...rest} />;
    }
}

Button.propTypes = {
    /** Set active state */
    active: PropTypes.bool,
    /** Additonal class to apply to the button */
    className: PropTypes.string,
    /** Error color scheme */
    danger: PropTypes.bool,
    /** Dark color scheme (can be used in conjunction with 'secondary') */
    dark: PropTypes.bool,
    /** Disable the button (no clicks) */
    disabled: PropTypes.bool,
    /** Forward React ref to the `<input>` element */
    innerRef: PropTypes.oneOfType([PropTypes.func, PropTypes.object]),
    /** Name of the `button` element */
    name: PropTypes.string,
    /** Disable animations / transitions */
    noanim: PropTypes.bool,
    /** Secondary color scheme */
    secondary: PropTypes.bool,
    /** Size of buttons (default is regular) */
    size: PropTypes.oneOf(['large', 'regular', 'small']),
    /** <button> type attribute */
    type: PropTypes.oneOf(['button', 'submit', 'reset']),
    /** <button> value attribute */
    value: PropTypes.any,
    /** Gets called when the button is clicked */
    onClick: PropTypes.func,
};

Button.defaultProps = {
    active: false,
    danger: false,
    dark: false,
    disabled: false,
    noanim: false,
    size: 'regular',
    secondary: false,
};

export default Button;
