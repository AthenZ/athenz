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

package com.yahoo.athenz.zms.notification;

import com.yahoo.athenz.zms.TagValueList;
import org.apache.commons.lang3.EnumUtils;

import java.util.EnumSet;
import java.util.Map;
import java.util.function.Function;

public enum DisableNotificationEnum {
    USER,          // disable notifications to the users
    ADMIN,         // disable notifications to the admins
    OVER_ONE_WEEK; // disable notifications to the users/admins if the expiry is more than a week out

    public static EnumSet<DisableNotificationEnum> getEnumSet(long mask) {
        return EnumUtils.processBitVector(DisableNotificationEnum.class, mask);
    }

    public static <T> EnumSet<DisableNotificationEnum> getDisabledNotificationState(T collection,
            Function<T, Map<String, TagValueList>> tagsGetter, final String disableNotificationTag) {

        if (collection == null) {
            return DisableNotificationEnum.getEnumSet(0);
        }

        Map<String, TagValueList> tags = tagsGetter.apply(collection);
        if (tags != null &&
                tags.get(disableNotificationTag) != null &&
                tags.get(disableNotificationTag).getList() != null &&
                !tags.get(disableNotificationTag).getList().isEmpty()) {
            String value = tags.get(disableNotificationTag).getList().get(0);
            return DisableNotificationEnum.getEnumSet(Integer.parseInt(value));
        }

        return DisableNotificationEnum.getEnumSet(0);
    }
}
