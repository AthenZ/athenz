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
class RequestUtils {
    static errorCheckHelper(err) {
        let reload = false;
        let error = null;
        if (err.statusCode === 0) {
            reload = true;
        }
        if (err.output) {
            error = {
                message: err.output.message,
                statusCode: err.statusCode,
            };
        }
        return { reload, error };
    }
    static xhrErrorCheckHelper(err) {
        let message;
        if (err && err.statusCode === 0) {
            message = 'Session expired. Please refresh the page.';
        } else if (
            err.body !== null &&
            err.body !== undefined &&
            err.body.message !== null &&
            err.body.message !== undefined
        ) {
            message = `Status: ${err.statusCode}. Message: ${err.body.message}`;
        } else {
            message = `Status: ${err.statusCode}.`;
        }
        return message;
    }
    static fetcherErrorCheckHelper(err) {
        let message;
        if (err && err.statusCode === 0) {
            message = 'Session expired. Please refresh the page.';
        } else if (err.output && err.output.message) {
            message = `Status: ${err.statusCode}. Message: ${err.output.message}`;
        } else if (err.body && err.body.message) {
            message = `Status: ${err.statusCode}. Message: ${err.body.message}`;
        } else {
            message = `Status: ${err.statusCode}`;
        }
        return message;
    }
}

export default RequestUtils;
