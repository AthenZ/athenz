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

package com.yahoo.athenz.zts.transportrules;

import com.yahoo.athenz.zts.TransportDirection;
import com.yahoo.athenz.zts.TransportRule;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class TransportRulesProcessor {
    private static final String TRANSPORT_RULES_ACTION_REGEX_PATTERN = "(TCP|UDP)-(IN|OUT):(\\d{1,5}-\\d{1,5}|\\d{1,5}):(\\d{1,5})";
    private static final Pattern TRANSPORT_RULES_PATTERN = Pattern.compile(TRANSPORT_RULES_ACTION_REGEX_PATTERN);

    public static boolean isTransportRuleAction(String action) {
        return TRANSPORT_RULES_PATTERN.matcher(action).find();
    }

    public static TransportRule parseTransportRuleAction(String action) {
        Matcher matcher = TRANSPORT_RULES_PATTERN.matcher(action);
        TransportRule transportRule = null;
        if (matcher.find()) {
            transportRule = new TransportRule();
            transportRule.setProtocol(matcher.group(1));
            transportRule.setDirection(TransportDirection.fromString(matcher.group(2)));
            transportRule.setSourcePortRange(matcher.group(3));
            transportRule.setPort(Integer.parseInt(matcher.group(4)));
        }
        return transportRule;
    }
}
