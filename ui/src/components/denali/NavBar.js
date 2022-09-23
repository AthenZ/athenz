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
import { cssDropShadow } from './styles/drop-shadow';

const makeCssNavBar = (props) => css`
    align-items: center;
    background: ${props.background};
    backface-visibility: hidden;
    box-sizing: border-box;
    color: ${colors.white};
    display: flex;
    flex: 0 0 60px;
    flex-flow: row nowrap;
    height: 60px;
    justify-content: flex-start;
    left: 0;
    padding: 0 24px;
    position: ${props.position};
    right: 0;
    top: 0;
    z-index: 2;
    label: navbar;

    &.scrolled {
        ${cssDropShadow};
    }

    & .flush-right {
        margin-left: auto;
    }
`;

/**
 * The goal of the NavBar component is to be a lightweight component that
 * composes the application header. Since each application has their own needs
 * -- menu items, search bar, sidebar toggle, denali-react provides basic CSS
 * building blocks for these without explicitly defining the logic. For example,
 * linking/routing is not provided since each application may be using a
 * different library (eg. `react-router`, `fluxible-router`, `aviator`) or have
 * their own custom implementation.
 */
class NavBar extends React.PureComponent {
    render() {
        const { background, className, position, ...rest } = this.props;
        const cssProps = { background, position };
        const cssNavBar = makeCssNavBar(cssProps);
        const classes = cx(cssNavBar, 'denali-navbar', className);
        return <div {...rest} className={classes} data-testid='navbar' />;
    }
}

NavBar.propTypes = {
    /**
     * Background CSS (normally a color). This can be a simple CSS color value or
     * any other valid CSS `background` value.
     */
    background: PropTypes.string,
    /**
     * Children to render inside `NavBar`
     * @ignore
     */
    children: PropTypes.any,
    /** Additonal class to apply to the outer div */
    className: PropTypes.string,
    /**
     * Set the CSS position of the navbar. This allows for various layout
     * implementations. If `fixed`, the NavBar will always be pinned to the top
     * of the page, and your app should take the 60px height of the navbar into
     * account. If set to `absolute` or `relative`, it is assumed the app already
     * has space allocated to the navbar (for example, as a flex/grid section)
     */
    position: PropTypes.oneOf([
        'fixed',
        'absolute',
        'relative',
        'static',
        'sticky',
    ]),
};

NavBar.defaultProps = {
    background: '#0b2b31',
    position: 'static',
};

export default NavBar;
