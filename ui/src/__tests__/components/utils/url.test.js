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
 * See the License for the specific language governing permissions and limitations
 * under the License.
 */
import { resolveZmsCliUrl } from '../../../components/utils/url';

describe('resolveZmsCliUrl', () => {
    it('returns runtime URL when set', () => {
        expect(resolveZmsCliUrl('https://zms.example.com:4443/zms/v1')).toBe(
            'https://zms.example.com:4443/zms/v1'
        );
    });

    it('returns null when runtime URL is missing or invalid', () => {
        expect(resolveZmsCliUrl(null)).toBeNull();
        expect(resolveZmsCliUrl(undefined)).toBeNull();
        expect(resolveZmsCliUrl('')).toBeNull();
        expect(resolveZmsCliUrl('   ')).toBeNull();
        expect(resolveZmsCliUrl(123)).toBeNull();
    });
});
