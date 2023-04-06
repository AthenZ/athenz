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

package sds

import (
	"testing"
)

func TestNewSubscriber(test *testing.T) {
	sub := NewSubscriber()
	if sub.GetId() == "" {
		test.Errorf("new subscriber does not have id")
	}
	if sub.certUpdChan == nil {
		test.Errorf("new subscriber does not update channel")
	}
	sub.Close()
}

func TestSubscriberNonce(test *testing.T) {
	sub := NewSubscriber()
	if sub.responseNonce != "" {
		test.Errorf("new subscriber has an expected nonce: %s", sub.responseNonce)
	}
	//without the nonce we should all nonce responses
	if !sub.ValidateResponseNonce("abc") {
		test.Errorf("subscriber empty nonce value was not validated as expected")
	}
	sub.SetResponseNonce("abcd")
	if sub.responseNonce != "abcd" {
		test.Errorf("subscriber does not have expected 'abcd' nonce: %s", sub.responseNonce)
	}
	if !sub.ValidateResponseNonce("abcd") {
		test.Errorf("subscriber 'abcd' nonce value was not validated as expected")
	}
	if sub.ValidateResponseNonce("xyz") {
		test.Errorf("subscriber mismatched 'xyz' nonce value was validated incorrectly")
	}
	sub.Close()
}

func TestSubscriberVersionInfo(test *testing.T) {
	sub := NewSubscriber()
	if sub.GetVersionInfo() != "0" {
		test.Errorf("new subscriber does not have an expected version info of 0: %s", sub.GetVersionInfo())
	}
	//for now validate does not return any failures, just logs
	sub.ValidateVersionInfo("0")
	sub.IncrementVersion()
	if sub.GetVersionInfo() != "1" {
		test.Errorf("new subscriber does not have an expected version info of 1: %s", sub.GetVersionInfo())
	}
	sub.Close()
}
