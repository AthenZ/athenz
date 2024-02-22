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

class AppUtils {
    static deepClone(obj) {
        return JSON.parse(JSON.stringify(obj));
    }

    /**
     * Iterate through a class methods and binds them to itself
     * @param classObj - the class object to bind
     */
    static bindClassMethods(classObj) {
        const prototype = classObj.constructor.prototype;
        const propertyNames = Object.getOwnPropertyNames(
            Object.getPrototypeOf(classObj)
        );
        for (const prop of propertyNames) {
            if (
                prop !== 'constructor' &&
                typeof prototype[prop] === 'function'
            ) {
                classObj[prop] = classObj[prop].bind(classObj);
            }
        }
    }

    /**
     * Safely executes a function and returns its result.
     * If an error occurs during execution, it returns a default value.
     * @param {Function} fn - The function to execute.
     * @param {*} defaultValue - The default value to return if an error occurs.
     * @returns {*} - The result of the function execution or the default value.
     */
    static getSafe(fn, defaultValue) {
        try {
            return fn();
        } catch (err) {
            return defaultValue;
        }
    }
}

export default AppUtils;
