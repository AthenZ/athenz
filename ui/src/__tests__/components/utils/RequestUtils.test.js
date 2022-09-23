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
import RequestUtils from '../../../components/utils/RequestUtils';

describe('RequestUtils', () => {
    it('should test', () => {
        let err = {
            statusCode: 0,
            output: {
                message: 'test-error',
            },
        };
        let result = RequestUtils.errorCheckHelper(err);
        let expectResult = {
            reload: true,
            error: {
                message: 'test-error',
                statusCode: 0,
            },
        };
        expect(result).toEqual(expectResult);
    });
});
