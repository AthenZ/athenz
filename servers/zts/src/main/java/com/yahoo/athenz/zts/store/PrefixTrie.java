/*
 *
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package com.yahoo.athenz.zts.store;

import java.util.Set;

public interface PrefixTrie<T> {
    /**
     * Insert value for prefix
     * @param prefix - Text that ends with a wildcard
     * @param value - A value to associate with text that start with the prefix
     */
    void insert(String prefix, T value);

    /**
     * Delete a prefix and value pair. If a prefix has more than one value then only the value will be deleted.
     * @param prefix - Text that ends with a wildcard
     * @param value - A value to associate with text that start with the prefix
     */
    void delete(String prefix, T value);

    /**
     * Get all values matching prefixes for the given text
     * @param text - text to check
     * @return - All values matching prefixes for the given text
     */
    Set<T> findMatchingValues(String text);
}
