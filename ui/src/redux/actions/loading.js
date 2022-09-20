/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

export const LOADING_IN_PROCESS = 'LOADING_IN_PROCESS';
export const loadingInProcess = (funcName) => ({
    type: LOADING_IN_PROCESS,
    payload: { funcName },
});

export const LOADING_SUCCESS = 'LOADING_SUCCESS';
export const loadingSuccess = (funcName) => ({
    type: LOADING_SUCCESS,
    payload: { funcName },
});

export const LOADING_FAILED = 'LOADING_FAILED';
export const loadingFailed = (funcName) => ({
    type: LOADING_FAILED,
    payload: { funcName },
});
