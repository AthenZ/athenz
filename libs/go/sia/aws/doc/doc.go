//
// Copyright The Athenz Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package doc

import (
	"encoding/json"
	"fmt"
)

func GetDocumentEntry(document []byte, attr string) (string, error) {
	var docMap map[string]interface{}
	err := json.Unmarshal(document, &docMap)
	if err != nil {
		return "", err
	}
	value, ok := docMap[attr]
	if !ok {
		return "", fmt.Errorf("document does not have an attribute with name %s", attr)
	}
	return value.(string), nil
}

// GetAccountId returns the "accountId" attribute from the document passed to it
func GetAccountId(document []byte) (string, error) {
	return GetDocumentEntry(document, "accountId")
}
