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
import { colors } from './styles/colors';
import { cssFontFamilies } from './styles/fonts';
import { rgba } from 'polished';
import Icon from '../denali/icons/Icon';
/**
 * Tags are used to display small pieces of information. There are three general
 * styles of tags: default, clickable, and removable.
 */
const makeCssTag = (props) => css`
    ${cssFontFamilies.default};
    background: ${props.disabled
        ? rgba(colors.black, 0.1)
        : props.clickable
        ? 'none'
        : 'rgba(53, 112, 244, 0.08)'};
    border-radius: ${props.small ? '11px' : '14px'};
    border: 1px solid ${props.clickable ? colors.link : 'transparent'};
    box-sizing: border-box;
    color: ${props.disabled
        ? rgba(colors.black, 0.2)
        : props.clickable
        ? colors.link
        : colors.black};
    cursor: ${props.disabled
        ? 'not-allowed'
        : props.clickable
        ? 'pointer'
        : undefined};
    display: inline-block;
    font-size: ${props.small ? '12px' : '14px'};
    height: ${props.small ? '22px' : '28px'};
    line-height: ${props.small ? '20px' : '26px'};
    margin: 3px;
    min-width: 50px;
    padding: 0 12px;
    position: relative;
    text-decoration: none;
    transition: ${!props.noanim ? 'all 0.2s ease-out' : undefined};
    vertical-align: top;
    white-space: nowrap;
    label: tag;
    &:hover {
        background: ${props.disabled ? rgba(colors.black, 0.1) : '#cbd9f9'};
    }
    & .tag-remove {
        align-items: center;
        background: #cbd9f9;
        border-radius: ${props.small ? '0 11px 11px 0' : '0 14px 14px 0'};
        box-shadow: none;
        box-sizing: border-box;
        display: flex;
        height: ${props.small ? '22px' : '28px'};
        justify-content: center;
        opacity: 0;
        padding-right: 2px;
        position: absolute;
        right: ${props.small ? '-11px' : '-14px'};
        top: -1px;
        transition: ${!props.noanim ? 'all 0.2s ease-out' : undefined};
        width: ${props.small ? '22px' : '28px'};
    }
    &:hover .tag-remove {
        box-shadow: -4px 0 5px -1px ${rgba(colors.black, 0.2)};
        opacity: 1;
        right: 0;
    }
`;

const Tag = (props) => {
    const {
        children,
        className,
        disabled,
        innerRef,
        noanim,
        small,
        onClick,
        onClickRemove,
    } = props;

    const cssProps = {
        disabled,
        noanim,
        small,
        clickable: Boolean(onClick),
    };
    const cssTag = makeCssTag(cssProps);

    return (
        <div
            className={cx(cssTag, 'denali-tag', className)}
            ref={innerRef}
            onClick={onClick}
            data-testid='tag'
        >
            {children}
            {onClickRemove && (
                <div className='tag-remove'>
                    <Icon
                        name='close'
                        color={rgba(colors.black, 0.6)}
                        colorHover={colors.black}
                        isLink
                        size={small ? '16px' : '20px'}
                        onClick={onClickRemove}
                    />
                </div>
            )}
        </div>
    );
};

Tag.propTypes = {
    /**
     * Children (usually text) to render inside tag
     * @ignore
     */
    children: PropTypes.any,
    /** Additonal class to apply to the outer div */
    className: PropTypes.string,
    /** Disable the tag */
    disabled: PropTypes.bool,
    /** Forward React ref to the outermost div of the component */
    innerRef: PropTypes.oneOfType([PropTypes.func, PropTypes.object]),
    /** Disable animations / transitions */
    noanim: PropTypes.bool,
    /** Toggle small tags */
    small: PropTypes.bool,
    /**
     * If an `onClick()` function is passed in, tag will be selectable.
     * **NOTE:** This is mutually exclusive with `onClickRemove()`
     */
    onClick: PropTypes.func,
    /**
     * If an `onClickRemove()` function is passed in, tag will have a remove button.
     * **NOTE:** This is mutually exclusivewith `onClick()`
     */
    onClickRemove: PropTypes.func,
    /**
     * Validator to ensure only one of `onClick()` / `onClickRemove()` is defined
     * @ignore
     */
    xorOnClick: function (props, propName, componentName) {
        if (props.onClick && props.onClickRemove) {
            return new Error(
                'Only one of `onClick` | `onClickRemove` canbe defined in `' +
                    componentName +
                    '`. Validation failed.'
            );
        }
    },
};

Tag.defaultProps = {
    disabled: false,
    noanim: false,
    small: false,
};

export default Tag;
