package com.yahoo.athenz.zms.purge;

import org.apache.commons.lang3.EnumUtils;

import java.util.EnumSet;

public enum PurgeResourcesEnum {
        ROLES, GROUPS;
        private static EnumSet<PurgeResourcesEnum> getEnumSet(long mask) {
            return EnumUtils.processBitVector(PurgeResourcesEnum.class, mask);
        }

        public static EnumSet<PurgeResourcesEnum> getPurgeResourcesState(long value) {
            return PurgeResourcesEnum.getEnumSet(value);
        }
}
