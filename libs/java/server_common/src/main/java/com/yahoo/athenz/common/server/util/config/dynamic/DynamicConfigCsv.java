/*
 * Copyright The Athenz Authors.
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
package com.yahoo.athenz.common.server.util.config.dynamic;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.yahoo.athenz.common.server.util.config.ConfigManager;

import jakarta.annotation.Nullable;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * Holds a comma-seperated-list value for some config-key - always up-to-date. <br>
 * Items are trimmed, and empty items are ignored. <br>
 * Getting the value is very cheap (performance-wise). <br>
 * This class attempt to convert each list-item into String / Double / Float / Long / Integer,
 *  and maintains a list per each type (e.g. if an item can't be converted to Long - it will not appear in the Longs list). <br>
 * <br>
 * Check if an item is specified in the comma-seperated-list: <ul>
 *     <li> {@link #hasItem(String)}
 *     <li> {@link #hasItem(double)}
 *     <li> {@link #hasItem(float)}
 *     <li> {@link #hasItem(long)}
 *     <li> {@link #hasItem(int)}
 * </ul>
 * Get an immutable ordered collection of all items: <ul>
 *     <li> {@link #getStringsList()}
 *     <li> {@link #getDoublesList()}
 *     <li> {@link #getFloatsList()}
 *     <li> {@link #getLongsList()}
 *     <li> {@link #getIntegersList()}
 * </ul>
 * Note that the {@link #get()} method returns the comma-seperated-list as-is.
 */
public class DynamicConfigCsv extends DynamicConfigString {

    private ImmutableList<String>  stringsList;
    private ImmutableSet<String>   stringsSet;
    private ImmutableList<Double>  doublesList;
    private ImmutableSet<Double>   doublesSet;
    private ImmutableList<Float>   floatsList;
    private ImmutableSet<Float>    floatsSet;
    private ImmutableList<Long>    longsList;
    private ImmutableSet<Long>     longsSet;
    private ImmutableList<Integer> integersList;
    private ImmutableSet<Integer>  integersSet;

    /** Construct a non-dynamic fixed value - that will never change */
    public DynamicConfigCsv(@Nullable String fixedValue) {
        super(fixedValue);
        valueHasChanged(fixedValue, null, null);
    }

    /** Construct a dynamic value - that may automatically change */
    public DynamicConfigCsv(
            ConfigManager configManager,
            String configKey,
            @Nullable String defaultValue) {
        super(configManager, configKey, defaultValue);
        registerChangeCallback(this::valueHasChanged);
        callChangeCallbacksNow(null);   // will call valueHasChanged()
    }

    public boolean hasItem(String item) {
        return stringsSet.contains(item);
    }
    public boolean hasItem(double item) {
        return doublesSet.contains(item);
    }
    public boolean hasItem(float item) {
        return floatsSet.contains(item);
    }
    public boolean hasItem(long item) {
        return longsSet.contains(item);
    }
    public boolean hasItem(int item) {
        return integersSet.contains(item);
    }

    public ImmutableList<String>  getStringsList() {
        return stringsList;
    }
    public ImmutableList<Double>  getDoublesList() {
        return doublesList;
    }
    public ImmutableList<Float>   getFloatsList() {
        return floatsList;
    }
    public ImmutableList<Long>    getLongsList() {
        return longsList;
    }
    public ImmutableList<Integer> getIntegersList() {
        return integersList;
    }

    /** Whenever the value changes - reset all sets/lists */
    private void valueHasChanged(String newValue, String oldValue, DynamicConfig<String> dynamicConfig) {

        List<String>  stringsList  = new LinkedList<>();
        Set<String>   stringsSet   = new HashSet<>();
        List<Double>  doublesList  = new LinkedList<>();
        Set<Double>   doublesSet   = new HashSet<>();
        List<Float>   floatsList   = new LinkedList<>();
        Set<Float>    floatsSet    = new HashSet<>();
        List<Long>    longsList    = new LinkedList<>();
        Set<Long>     longsSet     = new HashSet<>();
        List<Integer> integersList = new LinkedList<>();
        Set<Integer>  integersSet  = new HashSet<>();

        if (newValue != null) {
            for (String item : newValue.split(",")) {
                item = item.trim();
                if (!item.isEmpty()) {
                    stringsList.add(item);
                    stringsSet.add(item);

                    // If the item is double...
                    try {
                        double number = Double.parseDouble(item);
                        doublesList.add(number);
                        doublesSet.add(number);
                    } catch (NumberFormatException ignored) {
                    }

                    // If the item is float...
                    try {
                        float number = Float.parseFloat(item);
                        floatsList.add(number);
                        floatsSet.add(number);
                    } catch (NumberFormatException ignored) {
                    }

                    // If the item is long...
                    try {
                        long number = Long.parseLong(item);
                        longsList.add(number);
                        longsSet.add(number);
                    } catch (NumberFormatException ignored) {
                    }

                    // If the item is integer...
                    try {
                        int number = Integer.parseInt(item);
                        integersList.add(number);
                        integersSet.add(number);
                    } catch (NumberFormatException ignored) {
                    }
                }
            }
        }

        this.stringsList  = ImmutableList.copyOf(stringsList);
        this.stringsSet   = ImmutableSet.copyOf(stringsSet);
        this.doublesList  = ImmutableList.copyOf(doublesList);
        this.doublesSet   = ImmutableSet.copyOf(doublesSet);
        this.floatsList   = ImmutableList.copyOf(floatsList);
        this.floatsSet    = ImmutableSet.copyOf(floatsSet);
        this.longsList    = ImmutableList.copyOf(longsList);
        this.longsSet     = ImmutableSet.copyOf(longsSet);
        this.integersList = ImmutableList.copyOf(integersList);
        this.integersSet  = ImmutableSet.copyOf(integersSet);
    }
}
