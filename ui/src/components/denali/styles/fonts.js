/*
 * CopyrightAthenz Authors
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
import { colors } from './colors';

export const fontFamily = 'Helvetica, Arial, sans-serif';
export const fontFamilyMonospace = 'Droid Sans Mono, monospace';

export const cssFontFamilies = {
    default: css`
        font-family: ${fontFamily};
    `,
    monospace: css`
        font-family: ${fontFamilyMonospace};
    `,
};

export const cssFontSizes = {
    default: css`
        font-size: 14px;
    `,
    heading: css`
        font-size: 16px;
    `,
    title: css`
        font-size: 20px;
    `,
    subtitle: css`
        font-size: 12px;
    `,
};

export const cssFontWeights = {
    normal: css`
        font-weight: 300;
    `,
    bold: css`
        font-weight: 600;
    `,
};

export const cssFontStyles = {
    default: css`
        ${cssFontFamilies.default};
        ${cssFontSizes.default};
        ${cssFontWeights.normal};
    `,
    title: css`
        ${cssFontFamilies.default};
        ${cssFontSizes.title};
        ${cssFontWeights.bold};
    `,
    subtitle: css`
        color: ${colors.grey600};
        ${cssFontSizes.subtitle};
        ${cssFontWeights.normal};
        text-transform: uppercase;
    `,
};
