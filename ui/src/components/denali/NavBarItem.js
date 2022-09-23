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
import { cssFontSizes, cssFontFamilies } from './styles/fonts';

const makeCssNavBarItem = (props) => css`
    align-items: center;
    box-sizing: border-box;
    display: flex;
    height: 60px;
    position: relative;
    width: ${props.width};
    label: navbar-item;

    &.simple {
        color: ${colors.white};
        ${cssFontFamilies.default};
        ${cssFontSizes.heading};
        padding: 0 12px;
        transition: ${!props.noanim ? 'all 0.2s ease-in' : undefined};
        &.nav-link {
            cursor: pointer;
            &:hover {
                color: ${rgba(colors.white, 0.75)};
            }
        }
        &.active {
            box-shadow: inset 0 -4px 0 ${colors.brand600};
        }
        &.nav-link.active:hover {
            box-shadow: inset 0 -4px 0 ${rgba(colors.brand600, 0.75)};
        }
    }

    & .nav-title {
        align-items: center;
        color: ${colors.white};
        display: flex;
        ${cssFontFamilies.default};
        ${cssFontSizes.heading};
        height: 100%;
        padding: 0 12px;
        transition: ${!props.noanim ? 'all 0.2s ease-in' : undefined};
    }
    &.nav-link .nav-title {
        cursor: pointer;
    }
    &.active .nav-title,
    & .active.nav-title {
        box-shadow: inset 0 -4px 0 ${colors.brand600};
    }
    & .nav-title:hover {
        color: ${rgba(colors.white, 0.75)};
    }
    &.nav-link.active .nav-title:hover,
    &.nav-link .active.nav-title:hover {
        box-shadow: inset 0 -4px 0 ${rgba(colors.brand600, 0.75)};
    }

    /* Logo */
    & img.nav-logo {
        align-items: center;
        display: flex;
        height: 34px;
    }

    /* Icons */
    & .nav-icon,
    &:hover .nav-icon {
        width: 24px;
        height: 24px;
        & path,
        & ellipse,
        & rect,
        & circle {
            fill: ${colors.white};
            transition: ${!props.noanim ? 'all 0.2s ease-in' : undefined};
        }
    }
    &.nav-link:hover .nav-icon {
        & path,
        & ellipse,
        & rect,
        & circle {
            fill: ${rgba(colors.white, 0.75)};
        }
    }
`;

class NavBarItem extends React.PureComponent {
    render() {
        const {
            active,
            className,
            complex,
            link,
            noanim,
            right,
            width,
            ...rest
        } = this.props;

        const cssProps = { active, noanim, width };
        const cssNavBarItem = makeCssNavBarItem(cssProps);
        const classes = cx(
            cssNavBarItem,
            {
                simple: !complex,
                active,
                'flush-right': right,
                'nav-link': link,
            },
            'denali-navbar-item',
            className
        );
        return <div {...rest} className={classes} data-testid='navbar-item' />;
    }
}

NavBarItem.propTypes = {
    /**
     * Sets active state (blue underline).
     * NOTE: An alternative is to use `type="complex"` and apply `.active` to
     * the element with `.nav-title`
     */
    active: PropTypes.bool,
    /**
     * Children to render inside `NavBarItem`
     * @ignore
     */
    children: PropTypes.any,
    /** Additonal class to apply to the outer div */
    className: PropTypes.string,
    /**
     * By default, `<NavBarItem>` assumes the content is a simple string. If
     * `complex` is set, then the component can be another component or nested
     * HTML elements. The element to be displayed should have a `.nav-title` class
     * attacked to it. An example is creating a dropdown menu where the trigger is
     * the display element.
     */
    complex: PropTypes.bool,
    /**
     * Sets the item to be a link.
     * NOTE: This sets only the CSS. It's up to the developer to provide the
     * actual routing.
     */
    link: PropTypes.bool,
    /** Disable animations / transitions */
    noanim: PropTypes.bool,
    /**
     * Flush the element to the right.
     * NOTE: Only one element within `<NavBar>` should have this property set.
     */
    right: PropTypes.bool,
    /**
     * Any valid CSS width value.
     * NOTE: This includes 15px padding on the left and on the right.
     */
    width: PropTypes.string,
};

NavBarItem.defaultProps = {
    active: false,
    complex: false,
    link: false,
    right: false,
};

export default NavBarItem;
