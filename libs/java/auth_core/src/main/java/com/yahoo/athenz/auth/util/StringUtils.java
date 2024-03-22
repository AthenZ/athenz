/*
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
 */
package com.yahoo.athenz.auth.util;

import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class StringUtils {
    
    public static boolean isRegexMetaCharacter(char regexChar) {
        switch (regexChar) {
            case '^':
            case '$':
            case '.':
            case '|':
            case '[':
            case '+':
            case '\\':
            case '(':
            case ')':
            case '{':
                return true;
            default:
                return false;
        }
    }
    
    public static boolean containsMatchCharacter(String name) {
        return name.indexOf('*') != -1 || name.indexOf('?') != -1;
    }
    
    public static String patternFromGlob(String glob) {
        StringBuilder sb = new StringBuilder("^");
        int len = glob.length();
        for (int i = 0; i < len; i++) {
            char c = glob.charAt(i);
            if (c == '*') {
                sb.append(".*");
            } else if (c == '?') {
                sb.append('.');
            } else {
                if (isRegexMetaCharacter(c)) {
                    sb.append('\\');
                }
                sb.append(c);
            }
        }
        sb.append("$");
        return sb.toString();
    }
    
    public static boolean containsControlCharacter(String value) {
        
        // we're going to check if the string contains
        // any characters in the '00' through '1F' range
        // so anything smaller than a space
        
        int length = value.length();
        for (int i = 0; i < length; i++) {
            if (value.charAt(i) < ' ') {
                return true;
            }
        }
        return false;
    }
    
    public static boolean requestUriMatch(String uri, Set<String> uriSet,
            List<Pattern> uriList) {
        
        // first we're going to check if we have the uri in our set
        
        if (uriSet != null && uriSet.contains(uri)) {
            return true;
        }
        
        // if not in our set, we'll check our pattern list for a regex match
        
        if (uriList != null) {
            for (Pattern pattern : uriList) {
                Matcher matcher = pattern.matcher(uri);
                if (matcher.matches()) {
                    return true;
                }
            }
        }
        return false;
    }
    
    public static int countMatches(final CharSequence str, final char ch) {
        int count = 0;
        for (int i = 0; i < str.length(); i++) {
            if (str.charAt(i) == ch) {
                count++;
            }
        }
        return count;
    }
}
