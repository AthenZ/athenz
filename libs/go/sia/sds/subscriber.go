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
	"github.com/google/uuid"
	"log"
	"strconv"
)

type Subscriber struct {
	id            string
	certUpdChan   chan bool
	responseNonce string
	versionNumber int
}

func NewSubscriber() *Subscriber {
	return &Subscriber{
		id:          uuid.New().String(),
		certUpdChan: make(chan bool, 1),
	}
}

func (subscriber *Subscriber) Close() {
	close(subscriber.certUpdChan)
}

func (subscriber *Subscriber) GetId() string {
	return subscriber.id
}

func (subscriber *Subscriber) ValidateResponseNonce(responseNonce string) bool {
	if subscriber.responseNonce != "" && subscriber.responseNonce != responseNonce {
		log.Printf("ValidateResponseNonce: %s: nonce mismatch: subscriber: %s, request: %s\n", subscriber.id, subscriber.responseNonce, responseNonce)
		return false
	}
	return true
}

func (subscriber *Subscriber) ValidateVersionInfo(versionInfo string) bool {
	if subscriber.versionNumber != 0 && strconv.Itoa(subscriber.versionNumber) != versionInfo {
		log.Printf("ValidateVersionInfo: %s: version info mismatch: subscriber: %d, request: %s\n", subscriber.id, subscriber.versionNumber, versionInfo)
	}
	return true
}

func (subscriber *Subscriber) IncrementVersion() {
	subscriber.versionNumber++
}

func (subscriber *Subscriber) GetVersionInfo() string {
	return strconv.Itoa(subscriber.versionNumber)
}

func (subscriber *Subscriber) SetResponseNonce(nonce string) {
	subscriber.responseNonce = nonce
}

func (subscriber *Subscriber) GetCertUpdates() chan bool {
	return subscriber.certUpdChan
}

func (subscriber *Subscriber) Notify() {
	subscriber.certUpdChan <- true
}
