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
import { cx } from '@emotion/css';
import { cssArrow, makeCssPopperBox } from './styles';
import { usePopperTooltip } from 'react-popper-tooltip';
import 'react-popper-tooltip/dist/styles.css';

// Default offset when 'placement' ends with '-start' or '-end'
const DEFAULT_ARROW_OFFSET = 10;
const ARROW_SIZE = 16;

// Modifier to position the arrow depending on placement (start|end)
export const arrowMod = (data, options) => {
    if (data.placement.match(/(bottom|top)/)) {
        const popperWidth = data.offsets.popper.width;
        if (data.placement.match(/start/)) {
            data.arrowStyles.left = DEFAULT_ARROW_OFFSET + options.arrowOffset;
        } else if (data.placement.match(/end/)) {
            data.arrowStyles.left =
                popperWidth -
                ARROW_SIZE -
                DEFAULT_ARROW_OFFSET +
                options.arrowOffset;
        } else {
            data.arrowStyles.left += options.arrowOffset;
        }
    } else {
        const popperHeight = data.offsets.popper.height;
        if (data.placement.match(/start/)) {
            data.arrowStyles.top = DEFAULT_ARROW_OFFSET + options.arrowOffset;
        } else if (data.placement.match(/end/)) {
            data.arrowStyles.top =
                popperHeight -
                ARROW_SIZE -
                DEFAULT_ARROW_OFFSET +
                options.arrowOffset;
        } else {
            data.arrowStyles.top += options.arrowOffset;
        }
    }
    return data;
};

// Modifier to adjust the position
export const popperMod = (data, options) => {
    if (data.placement.match(/(bottom|top)/)) {
        data.styles.left += options.menuOffset;
    } else {
        data.styles.top += options.menuOffset;
    }
    return data;
};

/**
 * Menu component that activates on hovering over a trigger. This menu is based
 * on [PopperJS](https://popper.js.org/), a library to manage popups. The Menu
 * supports configurable positioning and method of activation (click or hover).
 * Menus are defined by the trigger (the element you interact with to open the
 * menu), and the menu content. Contrary to the name, the content does not have
 * to actually be a list of clickable items. Anything can go inside the popup.
 * Only the outer border box is styled by `<Menu>`; within the popup, you can
 * style it as you see it.
 *
 * Basic usage:
 *
 * ```bash
 * render() {
 *   const trigger = <span>Hover over me</span>;
 *   return (
 *     <Menu placement="bottom-start" trigger={trigger}>
 *       <ul>
 *         <a href="#">Section A</a>
 *         <a href="#">Section B</a>
 *       </ul>
 *     </Menu>
 *   );
 * }
 * ```
 *
 * If the content of the menu is a simple string (eg. `<Menu>some text</Menu>`),
 * then it will be wrapped in a `<span>` with `padding: 10px 20px`. Otherwise,
 * if you pass in a React node/element/component, no styling will be applied.
 *
 * NOTE: There is an issue where if the trigger is in a scrollable div, and the
 * menu is open, you cannot scroll if the cursor is over the menu. This is an
 * issue with the underlying `react-popper-tooltip` library, and it may be fixed
 * soon.
 *
 */
function Menu(props) {
    const renderTrigger = ({ getTriggerProps, triggerRef }) => {
        if (typeof props.trigger === 'function') {
            const renderedTrigger = props.trigger({
                getTriggerProps,
                triggerRef,
            });

            return renderedTrigger && React.Children.only(renderedTrigger);
        }

        let trigger;
        if (typeof props.trigger === 'string') {
            trigger = <span>{props.trigger}</span>;
        } else {
            trigger = props.trigger;
        }

        return React.cloneElement(trigger, {
            ...getTriggerProps({
                ref: triggerRef,
            }),
        });
    };

    // DEPRECATED: align will be deprecated, but support for now.
    let placement;
    if (props.align) {
        placement = `bottom-${props.align}`;
    } else {
        placement = props.placement;
    }
    let modifiers = {
        arrowMod: {
            arrowOffset: props.arrowOffset,
            enabled: true,
            order: 890,
            fn: arrowMod,
        },
        popperMod: {
            menuOffset: props.menuOffset,
            enabled: true,
            order: 880,
            fn: popperMod,
        },
        preventOverflow: {
            boundariesElement: props.boundary,
            padding: 0,
        },
    };

    const {
        getArrowProps,
        getTooltipProps,
        setTooltipRef,
        setTriggerRef,
        visible,
    } = usePopperTooltip(
        { trigger: props.triggerOn },
        {
            placement,
            modifiers,
        }
    );

    return (
        <>
            {renderTrigger({
                getTriggerProps: (props) => props,
                triggerRef: setTriggerRef,
            })}
            {visible && (
                <div
                    ref={setTooltipRef}
                    {...getTooltipProps({
                        className: cx(
                            makeCssPopperBox({
                                basic: typeof props.children === 'string',
                                noanim: props.noanim,
                            }),
                            props.className
                        ),
                        'data-placement': placement,
                    })}
                >
                    {props.children}
                    {!props.noArrow && (
                        <div
                            {...getArrowProps({
                                className: cssArrow,
                                'data-placement': placement,
                            })}
                        />
                    )}
                </div>
            )}
        </>
    );
}

Menu.propTypes = {
    /**
     * @deprecated
     *
     * Justify menu to the left or right side of the trigger
     */
    align: PropTypes.oneOf(['center', 'left', 'right']),
    /**
     * Change the offset position of the arrow. Positive values moves the arrow N
     * pixels to the right/down (depending on intiial top/bottom, left/right
     * placement), negative values to the left/up. If `align` is 'left' or
     * 'right', the arrow already has an offset of 10 pixels from the edge, so
     * `arrowOffset` is added on top of this internal offset.
     */
    arrowOffset: PropTypes.number,
    /**
     * Boundary of the tooltip that it must be contained within. This can be
     * either 'scrollParent', 'window', or 'viewport'. See:
     * https://popper.js.org/popper-documentation.html#modifiers..preventOverflow.boundariesElement
     */
    boundary: PropTypes.oneOf(['scrollParent', 'viewport', 'window']),
    /**
     * Content to render within the menu. This can be anything from a simple
     * string to a complex HTML markup to another React component.
     *
     * NOTE: If this is a simple string, it will be wrapped in a `<div>` with
     * some padding. If you want full control, pass in a pre-styled element.
     */
    children: PropTypes.node,
    /** Additonal class to apply to the popup div */
    className: PropTypes.string,
    /**
     * Change the offset position of the menu. Positive values moves the menu N
     * pixels to the right/down (depending on intiial top/bottom, left/right
     * placement), negative values to the left/up.
     */
    menuOffset: PropTypes.number,
    /** Disable animations / transitions */
    noanim: PropTypes.bool,
    /** Hide the arrow */
    noArrow: PropTypes.bool,
    /**
     * Called when visibility changes. Needed if 'showMenu' is used.
     */
    onVisibilityChange: PropTypes.func,
    /**
     * Placement of the menu. Note: if there is not enough space in the viewport
     * for the specified position, it will be placed on the opposite side
     * (eg. specified 'top', show on 'bottom')
     */
    placement: PropTypes.oneOf([
        'top',
        'top-start',
        'top-end',
        'bottom',
        'bottom-start',
        'bottom-end',
        'left',
        'left-start',
        'left-end',
        'right',
        'right-start',
        'right-end',
    ]),
    /**
     * Control prop.
     *
     * Use this prop if you want to control the visibility state of the menu.
     */
    showMenu: PropTypes.bool,
    /**
     * A React element representing the trigger (element to hover over). This can
     * be a simple string to another React component / element.
     *
     * NOTE: If this is a string, it will be wrapped in a `<span>` element.
     */
    trigger: PropTypes.oneOfType([PropTypes.node, PropTypes.func]).isRequired,
    /** Activate the menu on hover (default) or click */
    triggerOn: PropTypes.oneOf(['click', 'hover']),
    /**
     * Advanced - Use React Portal to render the menu.
     *
     * See: https://www.npmjs.com/package/react-popper-tooltip#useportal
     * And: https://github.com/FezVrasta/react-popper#usage-with-reactdomcreateportal
     */
    usePortal: PropTypes.bool,
};

Menu.defaultProps = {
    arrowOffset: 0,
    boundary: 'scrollParent',
    menuOffset: 0,
    noanim: false,
    noArrow: true,
    placement: 'bottom',
    triggerOn: 'hover',
    usePortal: false,
};

export default Menu;
