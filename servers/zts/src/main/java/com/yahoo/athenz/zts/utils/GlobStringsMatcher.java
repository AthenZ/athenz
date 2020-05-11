/*
 *  Copyright 2020 Verizon Media
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
 */

package com.yahoo.athenz.zts.utils;

import com.yahoo.athenz.common.server.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class GlobStringsMatcher {
    private static final Logger LOGGER = LoggerFactory.getLogger(GlobStringsMatcher.class);

    private final List<String> patterns;

    public GlobStringsMatcher(String systemProperty) {
        List<String> globList = ZTSUtils.splitCommaSeperatedSystemProperty(systemProperty);
        patterns = globList.stream().map(glob -> StringUtils.patternFromGlob(glob)).collect(Collectors.toList());
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Ignored Services Regex List: " + Arrays.toString(patterns.toArray()));
        }
    }

    public boolean isMatch(String value) {
        return patterns.stream().anyMatch(pattern -> value.matches(pattern));
    }
}
