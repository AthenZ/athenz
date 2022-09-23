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

/**
 * Use around a div (eg. modal)
 */
export const cssDropShadow = css`
    box-shadow: 0px 4px 8px rgba(0, 0, 0, 0.16);
`;

/**
 * Use under a header when scrolling content below it.
 */
export const cssScrollDropShadowTop = css`
    box-shadow: inset 0 5px 4px -2px rgba(48, 48, 48, 0.25);
`;

/**
 * Use above a footer when scrolling content above it.
 */
export const cssScrollDropShadowBottom = css`
    box-shadow: inset 0 -5px 4px -2px rgba(48, 48, 48, 0.25);
`;
