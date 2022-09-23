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
import { css } from '@emotion/css';
import { cssFontStyles } from '../styles/fonts';
import { colors } from '../styles/colors';
import { cssDropShadow } from '../styles/drop-shadow';

export const makeCssPopperBox = (props) => css`
    ${cssDropShadow};
    ${cssFontStyles.default};
    background-color: ${colors.white};
    border: 2px solid ${colors.border};
    border-radius: 4px;
    color: ${colors.black};
    cursor: default;
    line-height: 1.4;
    margin: 0;
    max-width: ${props.basic ? '400px' : undefined};
    min-width: 20px;
    padding: ${props.basic ? '6px 10px' : 0};
    transition: ${!props.noanim && 'opacity 0.25s ease-in'};
    z-index: 999;
    label: denali-menu;
    /* Shift the popper to allow space for arrow */
    &[data-placement*='bottom'] {
        margin-top: 8px;
    }
    &[data-placement*='top'] {
        margin-bottom: 8px;
    }
    &[data-placement*='left'] {
        margin-right: 8px;
    }
    &[data-placement*='right'] {
        margin-left: 8px;
    }

    /**
   * Invisible padding between trigger and main content (around the arrow) so
   * user can slide from one to the other without the menu closing.
   */
    &::after {
        background: transparent;
        content: '';
        position: absolute;
    }
    &[data-placement*='top']::after {
        bottom: -12px;
        height: 12px;
        width: 100%;
    }
    &[data-placement*='bottom']::after {
        height: 12px;
        top: -12px;
        width: 100%;
    }
    &[data-placement*='left']::after {
        right: -12px;
        height: 100%;
        width: 12px;
    }
    &[data-placement*='right']::after {
        left: -12px;
        height: 100%;
        width: 12px;
    }
`;

export const cssArrow = css`
    height: 1rem;
    position: absolute;
    width: 1rem;
    label: menu-arrow;

    &::before,
    &::after {
        border-style: solid;
        content: '';
        display: block;
        height: 0;
        margin: auto;
        position: absolute;
        width: 0;
    }

    &[data-placement*='bottom'] {
        left: 0;
        margin-top: -6px;
        top: -8px;
        width: 1rem;
    }

    &[data-placement*='bottom']::before {
        border-color: transparent transparent ${colors.grey400} transparent;
        border-width: 0 8px 8px 8px;
        position: absolute;
        top: 4px;
    }

    &[data-placement*='bottom']::after {
        border-color: transparent transparent ${colors.white} transparent;
        border-width: 0 8px 8px 8px;
        top: 7px;
    }

    &[data-placement*='top'] {
        bottom: 0;
        height: 1rem;
        left: 0;
        margin-bottom: -1rem;
        width: 1rem;
    }

    &[data-placement*='top']::before {
        border-color: ${colors.grey400} transparent transparent transparent;
        border-width: 8px 8px 0 8px;
        position: absolute;
        top: 2px;
    }

    &[data-placement*='top']::after {
        border-color: ${colors.white} transparent transparent transparent;
        border-width: 8px 8px 0 8px;
        top: -1px;
    }

    &[data-placement*='right'] {
        height: 1rem;
        left: 0;
        margin-left: -1rem;
        width: 1rem;
    }

    &[data-placement*='right']::before {
        border-color: transparent ${colors.grey400} transparent transparent;
        border-width: 8px 8px 8px 0;
        left: 5px;
    }

    &[data-placement*='right']::after {
        border-color: transparent ${colors.white} transparent transparent;
        border-width: 8px 8px 8px 0;
        left: 8px;
        top: 0;
    }

    &[data-placement*='left'] {
        height: 1rem;
        margin-right: -1rem;
        right: 0;
        width: 1rem;
    }

    &[data-placement*='left']::before {
        border-color: transparent transparent transparent ${colors.grey400};
        border-width: 8px 0 8px 8px;
        left: 2px;
    }

    &[data-placement*='left']::after {
        border-color: transparent transparent transparent ${colors.white};
        border-width: 8px 0 8px 8px;
        left: -1px;
        top: 0;
    }
`;
