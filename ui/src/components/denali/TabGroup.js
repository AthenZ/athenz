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
import { cssFontStyles } from './styles/fonts';
import { rgba } from 'polished';

const makeCssTabGroup = ({ secondary, length, equalWidth }) => css`
    align-items: stretch;
    background: ${secondary ? colors.white : colors.brand100};
    border-radius: 2px;
    box-shadow: ${secondary
        ? `inset 0 -2px 0 0 ${rgba(colors.brand700, 0.05)}`
        : undefined};
    box-sizing: border-box;
    display: inline-grid;
    grid-template-columns: repeat(${length}, ${equalWidth ? '1fr' : 'auto'});
    margin-top: ${secondary ? '-1px' : 0};
    min-width: 80px;
    position: relative;
    label: tab-group;

    &.vertical {
        background: ${colors.brand100};
        display: flex;
        flex-direction: column;
        height: 100%;
        min-width: 300px;
        overflow-y: scroll;
        padding: 12px 0px 40px 0px;
        width: 300px;
    }
`;

const makeCssTab = (props) => css`
    ${cssFontStyles.default};
    align-items: center;
    background: ${props.secondary ? 'transparent' : colors.brand100};
    border-bottom: ${props.secondary
        ? `solid 2px ${rgba(colors.brand100, 0.05)}`
        : undefined};
    color: ${props.disabled ? rgba(colors.black, 0.2) : colors.brand600};
    cursor: ${props.disabled ? 'not-allowed' : 'pointer'};
    display: flex;
    justify-content: center;
    padding: 8px 20px;
    transition: ${!props.noanim ? 'all 0.4s ease' : undefined};
    white-space: nowrap;
    z-index: 1;
    label: tab-group-tab;

    &:hover {
        color: ${props.disabled ? rgba(colors.black, 0.2) : colors.brand700};
    }

    &.active {
        background: ${colors.white};
        border-bottom: ${props.secondary
            ? `solid 2px ${colors.brand600}`
            : undefined};
        border-top-left-radius: 2px;
        border-top-right-radius: 2px;
        color: ${colors.black};
        cursor: initial;
        &:hover {
            color: ${colors.black};
        }
    }

    &.vertical {
        background: ${colors.brand100};
        border-left: solid 4px ${colors.brand100};
        height: 24px;
        justify-content: flex-start;
        padding: 12px 0px 12px 26px;
        text-align: left;
    }

    &.vertical.active {
        background: ${colors.white};
        border-left: solid 4px ${colors.brand600};
        color: ${colors.black};
        &:hover {
            color: ${colors.black};
        }
    }
`;

/**
 * TabGroup provides additional navigation within a page or sub-section of a
 * larger website. There are three modes - primary (colors), secondary (colors),
 * and vertical (using primary colors).
 */
class TabGroup extends React.PureComponent {
    getSelectedName = (props) => props.selectedName || props.tabs[0].name;

    render() {
        const {
            className,
            direction,
            equalWidth,
            id,
            noanim,
            secondary,
            tabs,
            onClick,
        } = this.props;

        if (!tabs.length) return null;

        const cssProps = {
            equalWidth,
            secondary,
            length: tabs.length,
            noanim,
        };
        const cssTabGroup = makeCssTabGroup(cssProps);
        const classNames = cx(
            cssTabGroup,
            'denali-tab-group',
            { vertical: direction === 'vertical' },
            className
        );

        const renderedTabs = tabs.map((tab) => {
            const selectedName = this.getSelectedName(this.props);
            const active = selectedName === tab.name;
            const cssProps = { disabled: tab.disabled, noanim, secondary };
            const cssTab = makeCssTab(cssProps);
            const classes = cx(
                cssTab,
                'denali-tab',
                {
                    active,
                    vertical: direction === 'vertical',
                },
                tab.className
            );

            let label;
            if (typeof tab.label === 'function') {
                label = tab.label();
            } else {
                label = tab.label;
            }

            const onClickTab = () => {
                if (!onClick || tab.disabled || active) {
                    return;
                }
                onClick(tab);
            };

            let shouldSplitOnParentheses = typeof(label) === 'string' && label.includes('(');
            if (shouldSplitOnParentheses) {
                let splitLabel = label.split('(');
                label = (
                    <span style={{ 'text-align': 'center' }}>
                        {splitLabel[0]}
                        <br />({splitLabel[1]}
                    </span>
                );
            };

            return (
                <div
                    className={classes}
                    data-active={active}
                    id={tab.id && `tab-${tab.id}`}
                    key={tab.name}
                    onClick={onClickTab}
                >
                    {label}
                </div>
            );
        });

        return (
            <div className={classNames} id={id} data-testid='tabgroup'>
                {renderedTabs}
            </div>
        );
    }
}

TabGroup.propTypes = {
    /** Additonal class to apply to the outer div */
    className: PropTypes.string,
    /** Direction of the tabs. */
    direction: PropTypes.oneOf(['horizontal', 'vertical']),
    /** Determine if tabs should be equal widths */
    equalWidth: PropTypes.bool,
    /** id to attach to outer div */
    id: PropTypes.string,
    /** Disable animations / transitions */
    noanim: PropTypes.bool,
    /** Primary color scheme (default) */
    primary: PropTypes.bool,
    /** Secondary color scheme */
    secondary: PropTypes.bool,
    /** Specifiy selected tab */
    selectedName: PropTypes.string,
    /** Array of tab configs */
    tabs: PropTypes.arrayOf(
        PropTypes.shape({
            name: PropTypes.string.isRequired,
            label: PropTypes.oneOfType([
                PropTypes.func,
                PropTypes.object,
                PropTypes.string,
            ]).isRequired,
            disable: PropTypes.bool,
            /** Class to apply to the actual tab */
            className: PropTypes.string,
            /** Additional data can be placed here that will be returned on `onClick()` */
            extra: PropTypes.object,
        })
    ).isRequired,
    /** Handler for the `onClick` event. Tab object returned as argument */
    onClick: PropTypes.func,
};

TabGroup.defaultProps = {
    direction: 'horizontal',
    equalWidth: true,
    noanim: false,
    primary: true,
    secondary: false,
};

export default TabGroup;
