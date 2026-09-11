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

package spiffe

import (
	"context"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/identity"
)

func TestIssuer(t *testing.T) {
	ctx := context.Background()
	url := "test-issuer-url"
	audience := "test-audience"
	issuer := Issuer(url, audience)

	// test the Match function
	t.Run("match", func(t *testing.T) {
		if matches := issuer.Match(ctx, url, audience); !matches {
			t.Fatal("expected url and audience to match but they don't")
		}
		if matches := issuer.Match(ctx, "some-other-url", audience); matches {
			t.Fatal("expected match to fail for different url but it didn't")
		}
		if matches := issuer.Match(ctx, url, "some-other-audience"); matches {
			t.Fatal("expected match to fail for different audience but it didn't")
		}
	})

	t.Run("authenticate", func(t *testing.T) {
		token := &oidc.IDToken{
			Issuer:  "https://issuer.example.com",
			Subject: "spiffe://example.com/foo/bar",
		}

		cfg := &config.FulcioConfig{
			OIDCIssuers: map[string]config.OIDCIssuer{
				"https://issuer.example.com": {
					IssuerURL:         "https://issuer.example.com",
					ClientID:          "sigstore",
					Type:              "spiffe",
					SPIFFETrustDomain: "example.com",
				},
			},
		}
		ctx := config.With(context.Background(), cfg)

		identity.Authorize = func(_ context.Context, _ string, _ ...config.InsecureOIDCConfigOption) (*oidc.IDToken, error) {
			return token, nil
		}
		principal, err := issuer.Authenticate(ctx, "token")
		if err != nil {
			t.Fatal(err)
		}

		if principal.Name(ctx) != "spiffe://example.com/foo/bar" {
			t.Fatalf("got unexpected name %s", principal.Name(ctx))
		}
	})
}
