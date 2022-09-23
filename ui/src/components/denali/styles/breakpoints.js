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
/**
 * Browser widths
 */
export const breakpoints = {
    mobile: {
        minWidth: 0,
        maxWidth: 599,
    },
    tablet: {
        minWidth: 600,
        maxWidth: 899,
    },
    'desktop-small': {
        minWidth: 900,
        maxWidth: 1199,
    },
    // Redefine as camelCase
    desktopSmall: {
        minWidth: 900,
        maxWidth: 1199,
    },
    'desktop-regular': {
        minWidth: 1200,
        maxWidth: 1439,
    },
    // Redefine as camelCase
    desktopRegular: {
        minWidth: 1200,
        maxWidth: 1439,
    },
    'desktop-hd': {
        minWidth: 1440,
        maxWidth: 90000, // Just define some obscenely large value
    },
    // Redefine as camelCase
    desktopHD: {
        minWidth: 1440,
        maxWidth: 90000,
    },
};
