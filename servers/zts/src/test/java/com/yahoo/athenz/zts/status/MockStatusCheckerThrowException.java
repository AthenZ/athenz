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

package com.yahoo.athenz.zts.status;

import com.yahoo.athenz.common.server.rest.ResourceException;
import com.yahoo.athenz.common.server.status.StatusCheckException;
import com.yahoo.athenz.common.server.status.StatusChecker;
import com.yahoo.athenz.common.server.status.StatusCheckerFactory;

public class MockStatusCheckerThrowException {

    public static final class NoArguments implements StatusCheckerFactory {
        @Override
        public StatusChecker create() {
            return () -> {
                throw new StatusCheckException();
            };
        }
    }

    public static final class NotFound implements StatusCheckerFactory {
        @Override
        public StatusChecker create() {
            return () -> {
                throw new StatusCheckException(ResourceException.NOT_FOUND);
            };
        }
    }

    public static final class InternalServerErrorWithMessage implements StatusCheckerFactory {
        @Override
        public StatusChecker create() {
            return () -> {
                throw new StatusCheckException(ResourceException.INTERNAL_SERVER_ERROR, "error message");
            };
        }
    }

    public static final class CauseRuntimeException implements StatusCheckerFactory {
        @Override
        public StatusChecker create() {
            return () -> {
                throw new StatusCheckException(new RuntimeException("runtime exception"));
            };
        }
    }
}
