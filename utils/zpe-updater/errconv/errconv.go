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

package errconv

import (
	"fmt"
	"strings"
)

// Reduces non nil-errors from a list of errors into a single error
func Reduce(es []error) error {
	if len(es) == 0 {
		return nil
	}

	list := []string{}
	for _, err := range es {
		if err != nil {
			list = append(list, fmt.Sprintf("%s", err))
		}
	}

	if len(list) == 0 {
		return nil
	}

	return fmt.Errorf("%d error(s) occurred: %s", len(list), strings.Join(list, "; "))
}
