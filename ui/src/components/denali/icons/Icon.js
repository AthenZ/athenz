/*
 * Copyright 2020 Verizon Media
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
import P, { PropTypes } from 'prop-types';
import { ICONS } from './Icons';
import { css } from 'emotion';

const Icon = (props) => {
    const icon = ICONS[props.icon];
    const width = props.size ? props.size : props.width;
    const height = props.size ? props.size : props.height;
    return (
        <svg
            viewBox='0 0 1024 1024'
            width={width}
            height={height}
            className={css`
                fill: ${props.color};
                cursor: ${props.isLink ? 'pointer' : 'inherit'};
                vertical-align: ${props.verticalAlign};
            `}
            onClick={props.onClick}
            ref={props.innerRef}
            data-testid='icon'
        >
            <title>{props.icon}</title>
            {icon.map((path, index) => (
                <path key={index} d={path} />
            ))}
        </svg>
    );
};

Icon.propTypes = {
    icon: PropTypes.string.isRequired,
    /* Can be any CSS size (eg. 16px, 1rem, 1.725em). Default: 1rem */
    size: PropTypes.string,
    /* can be used when size height and width are different */
    width: PropTypes.string,
    height: PropTypes.string,
    /* Can be any CSS color (eg. 'red', '#fff', rgba(128, 34, 64, 0.3)) */
    color: PropTypes.string,
    /* Default: text-bottom */
    verticalAlign: PropTypes.string,
    /* Click handler */
    onClick: PropTypes.func,
    isLink: PropTypes.bool,
    innerRef: P.oneOfType([P.func, P.object]),
};

Icon.defaultProps = {
    icon: 'x',
    size: '1em',
    verticalAlign: 'text-bottom',
};

export default Icon;
