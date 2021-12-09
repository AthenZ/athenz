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

package metrics

import (
	"encoding/json"
	"fmt"
	"time"
)

type Metric struct {
	Application string             `json:"application"`
	Dimensions  map[string]string  `json:"dimensions"`
	Metrics		map[string]interface{} `json:"metrics,omitempty"`
}

type StatusMetric struct {
	Application string `json:"application"`
	Code        int    `json:"status_code"`
	Message     string `json:"status_msg"`
}

type PolicyStatus struct {
	Name     		string
	ValidSignature 	bool
	FileExists      bool
	Expiry 			time.Duration
}

// NewMetric creates a metric type initialized to application 'zpu-check'
func NewMetric() *Metric {
	return &Metric{
		Application: "zpu-check",
	}
}

func NewStatusMetric() *StatusMetric {
	return &StatusMetric{
		Application: "zpu-check",
	}
}

func DumpMetric(metric *Metric, err error) ([]byte, error) {
	bytes, e := json.Marshal(metric)
	if e != nil {
		return nil, e
	}
	return bytes, nil
}

func DumpStatus(err error) ([]byte, bool, error) {
	status := NewStatusMetric()

	if err == nil {
		status.Code = 0
		status.Message = "All policy files are valid"
	} else {
		status.Code = 1
		status.Message = err.Error()
	}
	bytes, e := json.Marshal(status)
	if e != nil {
		return bytes, err == nil, e
	}
	return bytes, err == nil, e
}

func FormPolicyMetrics(policiesStatus []PolicyStatus) []*Metric {
	var policyMetrics []*Metric
	if policiesStatus != nil {
		for _, policyStatus := range policiesStatus {
			policyMetric := NewMetric()
			policyMetric.Dimensions = map[string]string{
				"policy_name": policyStatus.Name,
			}
			policyMetric.Metrics = make(map[string]interface{})
			policyMetric.Metrics["policy_expiry_minutes"] = float64(policyStatus.Expiry.Minutes())
			policyMetric.Metrics["valid_signature"] = policyStatus.ValidSignature
			policyMetric.Metrics["file_exists"] = policyStatus.FileExists
			policyMetrics = append(policyMetrics, policyMetric)
		}
	}
	return policyMetrics
}

func GetFailedStatus(err error) string {
	return fmt.Sprintf("{\"application\":\"zpu-check\",\"status_code\":1,\"status_msg\":\"%s\"}", err.Error())
}