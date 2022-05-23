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

package com.yahoo.athenz.common.server.msd.net;

import java.net.InetAddress;

public class InetComparator {
    public static int compare(InetAddress a, InetAddress b) {
        byte[] left = a.getAddress();
        byte[] right = b.getAddress();

        if (left.length != right.length) {
            throw new IllegalArgumentException(String.format("both %s and %s should be of the same IP type", a, b));
        }

        int result = 0;
        for (int i = 0; i < left.length; i++) {
            result = Integer.compare(Byte.toUnsignedInt(left[i]), Byte.toUnsignedInt(right[i]));
            if (result != 0) {
                break;
            }
        }

        return result;
    }
}
