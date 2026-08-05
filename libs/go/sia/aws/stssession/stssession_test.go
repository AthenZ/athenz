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

package stssession

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/sts/types"
)

// capturedArgs records the arguments passed to the stub fetcher.
type capturedArgs struct {
	useRegionalSTS bool
	region         string
	audience       string
	signingAlgorithm string
	durationSeconds int32
	tags           []types.Tag
}

func stubFetcher(returnToken string, returnErr error) (func(bool, string, string, string, int32, []types.Tag) (string, error), *capturedArgs) {
	cap := &capturedArgs{}
	fn := func(useRegionalSTS bool, region, audience, signingAlgorithm string, durationSeconds int32, tags []types.Tag) (string, error) {
		cap.useRegionalSTS = useRegionalSTS
		cap.region = region
		cap.audience = audience
		cap.signingAlgorithm = signingAlgorithm
		cap.durationSeconds = durationSeconds
		cap.tags = tags
		return returnToken, returnErr
	}
	return fn, cap
}

func TestGetWebIdentityToken_PassesCorrectArgs(t *testing.T) {
	orig := WebIdentityTokenFetcher
	defer func() { WebIdentityTokenFetcher = orig }()

	stub, cap := stubFetcher("fake.jwt.token", nil)
	WebIdentityTokenFetcher = stub

	tok, err := GetWebIdentityToken(false, "us-east-1", "https://zts.example.com", "ES384", 120, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "fake.jwt.token" {
		t.Errorf("expected token 'fake.jwt.token', got %q", tok)
	}
	if cap.audience != "https://zts.example.com" {
		t.Errorf("expected audience 'https://zts.example.com', got %q", cap.audience)
	}
	if cap.signingAlgorithm != "ES384" {
		t.Errorf("expected signingAlgorithm 'ES384', got %q", cap.signingAlgorithm)
	}
	if cap.durationSeconds != 120 {
		t.Errorf("expected durationSeconds 120, got %d", cap.durationSeconds)
	}
	if len(cap.tags) != 0 {
		t.Errorf("expected no tags, got %v", cap.tags)
	}
}

func TestGetWebIdentityToken_PropagatesError(t *testing.T) {
	orig := WebIdentityTokenFetcher
	defer func() { WebIdentityTokenFetcher = orig }()

	stub, _ := stubFetcher("", fmt.Errorf("sts unavailable"))
	WebIdentityTokenFetcher = stub

	_, err := GetWebIdentityToken(false, "us-east-1", "https://zts.example.com", "ES384", 120, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGetWebIdentityToken_WithTags(t *testing.T) {
	orig := WebIdentityTokenFetcher
	defer func() { WebIdentityTokenFetcher = orig }()

	key := "env"
	val := "prod"
	tags := []types.Tag{{Key: &key, Value: &val}}
	stub, cap := stubFetcher("tok", nil)
	WebIdentityTokenFetcher = stub

	_, err := GetWebIdentityToken(false, "us-west-2", "https://zts.example.com", "RS256", 300, tags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cap.tags) != 1 {
		t.Errorf("expected 1 tag, got %d", len(cap.tags))
	}
	if *cap.tags[0].Key != "env" || *cap.tags[0].Value != "prod" {
		t.Errorf("unexpected tag: %v", cap.tags[0])
	}
}
