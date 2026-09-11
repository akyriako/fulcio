// Copyright 2023 The Sigstore Authors.
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

package base

import (
	"context"
	"testing"
)

func TestMatch(t *testing.T) {
	tests := []struct {
		description string
		issuerURL   string
		clientID    string
		url         string
		audiences   []string
		expected    bool
	}{
		{
			description: "standard url and audience",
			issuerURL:   "example.com",
			clientID:    "sigstore",
			url:         "example.com",
			audiences:   []string{"sigstore"},
			expected:    true,
		},
		{
			description: "url matches but audience does not",
			issuerURL:   "example.com",
			clientID:    "sigstore",
			url:         "example.com",
			audiences:   []string{"other"},
			expected:    false,
		},
		{
			description: "url doesn't match",
			issuerURL:   "example.com",
			clientID:    "sigstore",
			url:         "something-else.com",
			audiences:   []string{"sigstore"},
			expected:    false,
		},
		{
			description: "matching audience among multiple audiences",
			issuerURL:   "example.com",
			clientID:    "sigstore",
			url:         "example.com",
			audiences:   []string{"other", "sigstore"},
			expected:    true,
		},
		{
			description: "valid meta issuer and audience",
			issuerURL:   "wildcard.*.example.com",
			clientID:    "sigstore",
			url:         "wildcard.hello.example.com",
			audiences:   []string{"sigstore"},
			expected:    true,
		},
		{
			description: "valid meta issuer with wrong audience",
			issuerURL:   "wildcard.*.example.com",
			clientID:    "sigstore",
			url:         "wildcard.hello.example.com",
			audiences:   []string{"other"},
			expected:    false,
		},
		{
			description: "invalid meta issuer match",
			issuerURL:   "wildcard.*.example.com",
			clientID:    "sigstore",
			url:         "wildcard.helloexample.com",
			audiences:   []string{"sigstore"},
			expected:    false,
		},
		{
			description: "empty configured client ID preserves URL-only matching",
			issuerURL:   "example.com",
			clientID:    "",
			url:         "example.com",
			expected:    true,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			issuer := Issuer(test.issuerURL, test.clientID)

			matched := issuer.Match(
				context.Background(),
				test.url,
				test.audiences...,
			)

			if matched != test.expected {
				t.Fatalf("expected %v got %v", test.expected, matched)
			}
		})
	}
}

func TestAuthenticate(t *testing.T) {
	issuer := Issuer("example.com", "sigstore")

	if _, err := issuer.Authenticate(context.Background(), "token"); err == nil {
		t.Fatal("expected error on authenticate, BaseIssuer shouldn't implement Authenticate")
	}
}
