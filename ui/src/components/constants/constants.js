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
import * as data from '../../config/zms.json';

export const MODAL_TIME_OUT = 2000;
export const GROUP_NAME_REGEX = data.types[3].StringTypeDef.pattern;
export const GROUP_MEMBER_NAME_REGEX = data.types[14].StringTypeDef.pattern;
export const GROUP_ROLES_CATEGORY = 'group-roles';
export const GROUP_MEMBER_PLACEHOLDER = 'user.<userid> or <domain>.<service>';
export const DISPLAY_SPACE = '\u23b5';

export const SERVICE_TYPE_DYNAMIC = 'dynamic';
export const SERVICE_TYPE_STATIC = 'static';
export const SERVICE_TYPE_DYNAMIC_LABEL = 'Dynamic';
export const SERVICE_TYPE_STATIC_LABEL = 'Static';

export const SERVICE_TABS = [
    {
        label: SERVICE_TYPE_STATIC_LABEL,
        name: SERVICE_TYPE_STATIC,
    },
    {
        label: SERVICE_TYPE_DYNAMIC_LABEL,
        name: SERVICE_TYPE_DYNAMIC,
    },
];
