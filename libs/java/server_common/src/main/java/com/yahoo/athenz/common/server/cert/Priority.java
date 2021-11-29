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

package com.yahoo.athenz.common.server.cert;

/**
 * Priority for certificate handling by crypki
 */
public enum Priority {
    // The values must match the values in https://github.com/theparanoids/crypki/blob/main/proto/sign.proto#L33
    Unspecified_priority(0),
    High(5),
    Medium(10),
    Low(15);

    public final int getPriorityValue() {
        return value;
    }

    private final int value;

    Priority(int value) {
        this.value = value;
    }
}
