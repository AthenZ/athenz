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

const makeCssButtonGroup = (props) => css`
    align-items: stretch;
    background: ${props.dark
        ? rgba(colors.grey300, 0.1)
        : rgba(colors.brand700, 0.05)};
    border-radius: 2px;
    box-sizing: border-box;
    display: inline-grid;
    grid-template-columns: repeat(${props.length}, 1fr);
    height: 28px;
    position: relative;
    label: button-group;

    /* Active box */
    &::before {
        background: ${colors.white};
        border: 2px solid ${colors.blue500};
        border-radius: 2px;
        box-sizing: border-box;
        content: '';
        height: calc(100% + 4px);
        margin: -2px -2px -2px calc(${props.marginRight}% - 2px);
        position: absolute;
        transition: ${!props.noanim ? 'all 0.3s ease-in' : undefined};
        width: calc(${props.segmentPct}% + 4px);
        label: button-group-active-box;
    }
`;

const makeCssButton = (props) => css`
    align-items: center;
    border-radius: 2px;
    box-sizing: border-box;
    color: ${props.active ? colors.black : colors.brand600};
    cursor: ${props.active ? 'initial' : 'pointer'};
    display: flex;
    ${cssFontStyles.default};
    justify-content: center;
    margin: 3px;
    padding: 0 12px;
    transition: ${!props.noanim ? 'color 0.2s ease-in 0.1s' : undefined};
    white-space: nowrap;
    z-index: 1;
    label: button-group-button;
    &:hover {
        color: ${props.active ? colors.black : colors.brand700};
    }
`;

class ButtonGroup extends React.PureComponent {
    render() {
        const { buttons, className, dark, id, noanim, selectedName } =
            this.props;

        if (!buttons.length) return null;

        const selected = selectedName || buttons[0].name;
        const activeIdx = buttons.findIndex((b) => b.name === selected);

        const renderedButtons = buttons.map((button) => {
            const active = selected === button.name;
            const cssProps = { active, noanim };
            const cssButton = makeCssButton(cssProps);
            return (
                <div
                    className={cssButton}
                    data-active={active}
                    id={button.id ? `button-${button.id}` : undefined}
                    key={button.name}
                    onClick={() => !active && this.props.onClick(button)}
                >
                    {button.label}
                </div>
            );
        });

        const length = this.props.buttons.length;
        const segmentPct = 100 / length;
        const marginRight = activeIdx * segmentPct;
        const cssProps = {
            dark,
            length,
            noanim,
            segmentPct,
            marginRight,
        };

        const cssButtonGroup = makeCssButtonGroup(cssProps);
        const classes = cx(cssButtonGroup, 'denali-button-group', className);

        return (
            <div className={classes} id={id} data-testid='buttongroup'>
                {renderedButtons}
            </div>
        );
    }
}

ButtonGroup.propTypes = {
    /** Array of button configs */
    buttons: PropTypes.arrayOf(
        PropTypes.shape({
            name: PropTypes.string.isRequired,
            label: PropTypes.string.isRequired,
            id: PropTypes.string,
            /** Additional data can be placed here that will be returned on `onClick()` */
            extra: PropTypes.object,
        })
    ).isRequired,
    /** Additonal class to apply to the outer div */
    className: PropTypes.string,
    /** Dark color scheme (can be used in conjunction with `primary`/`secondary`) */
    dark: PropTypes.bool,
    /** id to attach to outer div */
    id: PropTypes.string,
    /** Disable animations / transitions */
    noanim: PropTypes.bool,
    /** Handler for button click. The clicked button config is returned */
    onClick: PropTypes.func.isRequired,
    /** Specifiy selected button. Defaults to the first button */
    selectedName: PropTypes.string,
};

ButtonGroup.defaultProps = {
    dark: false,
    noanim: false,
};

export default ButtonGroup;
