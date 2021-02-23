/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.common.server.log.jetty;

public class ExceptionCauseFetcher {
    private static final int MAX_RECOURSE_CALLS = 100;
    public static String getInnerCause(Throwable exception, String originalMessage) {
        return getInnerCause(exception, originalMessage, MAX_RECOURSE_CALLS);
    }

    private static String getInnerCause(Throwable exception, String originalMessage, int maxRecourseCalls) {
        if (exception.getCause() == null || maxRecourseCalls == 0) {
            return originalMessage;
        }
        return getInnerCause(exception.getCause(), exception.getCause().getMessage(), --maxRecourseCalls);
    }
}
