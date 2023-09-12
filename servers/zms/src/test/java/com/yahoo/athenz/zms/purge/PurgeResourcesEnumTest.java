package com.yahoo.athenz.zms.purge;

import org.testng.annotations.Test;

import java.util.Arrays;
import java.util.EnumSet;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

public class PurgeResourcesEnumTest {

    @Test
    public void testState() {
        // None will be purged
        long mask = 0;
        EnumSet<PurgeResourcesEnum> enumSet = PurgeResourcesEnum.getPurgeResourcesState(mask);
        assertTrue(enumSet.isEmpty());

        // Roles will be purged
        mask = 1;
        enumSet = PurgeResourcesEnum.getPurgeResourcesState(mask);
        assertEquals(enumSet.size(), 1);
        assertTrue(enumSet.contains(PurgeResourcesEnum.ROLES));

        // Groups will be purged
        mask = 2;
        enumSet = PurgeResourcesEnum.getPurgeResourcesState(mask);
        assertEquals(enumSet.size(), 1);
        assertTrue(enumSet.contains(PurgeResourcesEnum.GROUPS));

        // Both will be purged
        mask = 3;
        enumSet = PurgeResourcesEnum.getPurgeResourcesState(mask);
        assertEquals(enumSet.size(), 2);
        assertTrue(enumSet.containsAll(Arrays.asList(PurgeResourcesEnum.ROLES, PurgeResourcesEnum.GROUPS)));

    }
}
