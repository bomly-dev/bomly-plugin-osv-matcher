package plugin

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	audcache "github.com/bomly-dev/bomly-sdk/filecache"
)

type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("network disabled")
}

// A catalog served from the file cache must carry its IDs: the cache stores
// the catalog through encoding/json, and a type with no exported state is
// written as an empty object that still counts as a hit.
func TestFetchKEVCatalog_CacheRoundTripKeepsIDs(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"vulnerabilities":[{"cveID":"CVE-2021-44228"},{"cveID":"CVE-2023-4863"}]}`))
	}))
	defer srv.Close()

	cache, err := audcache.NewFileCache(t.TempDir(), time.Hour)
	if err != nil {
		t.Fatalf("NewFileCache: %v", err)
	}

	// The test server stands in for www.cisa.gov: FetchKEVCatalog fetches a
	// constant URL, so the first call goes through a transport that rewrites
	// every request to the test server.
	live := &http.Client{Transport: rewriteTransport{target: srv.URL}}
	first, err := FetchKEVCatalog(cache, live)
	if err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	if !first.Contains("CVE-2021-44228", nil) {
		t.Fatalf("live catalog lacks CVE-2021-44228")
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}

	offline := &http.Client{Transport: failingTransport{}}
	second, err := FetchKEVCatalog(cache, offline)
	if err != nil {
		t.Fatalf("cached fetch: %v", err)
	}
	for _, id := range []string{"CVE-2021-44228", "CVE-2023-4863"} {
		if !second.Contains(id, nil) {
			t.Fatalf("cached catalog lacks %s: the cache stored an empty catalog", id)
		}
	}
	if second.Contains("CVE-2000-0001", []string{"GHSA-none"}) {
		t.Fatalf("cached catalog contains an ID that was never served")
	}
	if calls != 1 {
		t.Fatalf("calls = %d after a cached fetch, want 1", calls)
	}
}

type rewriteTransport struct{ target string }

func (r rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	target, err := req.URL.Parse(r.target + req.URL.Path)
	if err != nil {
		return nil, err
	}
	clone.URL = target
	clone.Host = target.Host
	return http.DefaultTransport.RoundTrip(clone)
}
