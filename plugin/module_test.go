package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	sdk "github.com/bomly-dev/bomly-sdk"
	"github.com/bomly-dev/bomly-sdk/conformance"
	"go.uber.org/zap"
)

// testHost is a minimal HostContext for unit tests.
type testHost struct {
	config json.RawMessage
}

func (h testHost) Logger() *zap.Logger                 { return zap.NewNop() }
func (h testHost) HTTPClient() *sdk.HTTPClientProvider { return nil }
func (h testHost) Runtime() sdk.RuntimeInfo {
	return sdk.RuntimeInfo{Execution: sdk.ExecutionEmbedded}
}

func (h testHost) DecodeConfig(v any) error {
	payload := h.config
	if len(payload) == 0 {
		payload = json.RawMessage("{}")
	}
	return json.Unmarshal(payload, v)
}

// TestModuleConstructsMatcher checks the managed constructor honors the JSON
// config block.
func TestModuleConstructsMatcher(t *testing.T) {
	cacheDir := filepath.ToSlash(filepath.Join(t.TempDir(), "cache"))
	cfg := fmt.Sprintf(`{"api_base":"https://api.osv.example","cache_dir":%q,"cache_ttl":"12h","disable_kev":true}`, cacheDir)
	component, err := Module().Matcher.New(context.Background(), testHost{config: json.RawMessage(cfg)})
	if err != nil {
		t.Fatalf("construct matcher: %v", err)
	}
	matcher, ok := component.(*Matcher)
	if !ok {
		t.Fatalf("unexpected component type %T", component)
	}
	if matcher.config.APIBase != "https://api.osv.example" {
		t.Fatalf("api base = %q", matcher.config.APIBase)
	}
	if matcher.config.EnableKEV {
		t.Fatal("expected KEV to be disabled")
	}
}

// newOSVServer serves a small OSV fixture: one advisory for any queried batch
// entry.
func newOSVServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			var req BatchRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			results := make([]BatchResult, len(req.Queries))
			for i := range results {
				results[i] = BatchResult{Vulns: []VulnRef{{ID: "OSV-2024-0001"}}}
			}
			_ = json.NewEncoder(w).Encode(BatchResponse{Results: results})
		case "/v1/vulns/OSV-2024-0001":
			_ = json.NewEncoder(w).Encode(Vulnerability{ID: "OSV-2024-0001", Summary: "Test vuln", Severity: []Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func newDeltaTestGraph(t *testing.T) *sdk.Graph {
	t.Helper()
	graph := sdk.New()
	dep := sdk.NewDependencyRef("vulnerable-pkg", "1.0.0")
	dep.PURL = "pkg:npm/vulnerable-pkg@1.0.0"
	dep.Ecosystem = sdk.EcosystemNPM
	if err := graph.AddNode(dep); err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	return graph
}

func newDeltaMatcher(t *testing.T, apiBase string) *Matcher {
	t.Helper()
	matcher, err := New(Config{APIBase: apiBase, CacheDir: t.TempDir(), VulnDetailCacheDir: t.TempDir(), EnableKEV: false})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return matcher
}

// TestMatchDeltaEquivalence is the delta-protocol contract check: when the
// request sets AcceptPackageUpdates, Match must leave the request registry
// untouched and return deltas that — applied through the host's own merge,
// sdk.ApplyPackageUpdates — reproduce the registry the legacy full-registry
// path produces.
func TestMatchDeltaEquivalence(t *testing.T) {
	server := newOSVServer(t)

	legacyRegistry := sdk.NewPackageRegistry()
	legacy, err := newDeltaMatcher(t, server.URL).Match(context.Background(), sdk.MatchRequest{
		Graph:    newDeltaTestGraph(t),
		Registry: legacyRegistry,
	})
	if err != nil {
		t.Fatalf("legacy Match() error = %v", err)
	}

	deltaRegistry := sdk.NewPackageRegistry()
	delta, err := newDeltaMatcher(t, server.URL).Match(context.Background(), sdk.MatchRequest{
		Graph:                newDeltaTestGraph(t),
		Registry:             deltaRegistry,
		AcceptPackageUpdates: true,
	})
	if err != nil {
		t.Fatalf("delta Match() error = %v", err)
	}

	if delta.Registry != nil {
		t.Fatal("delta path must not return a registry")
	}
	if len(delta.PackageUpdates) != 1 {
		t.Fatalf("expected 1 package update, got %d", len(delta.PackageUpdates))
	}
	update := delta.PackageUpdates[0]
	if update.PURL != "pkg:npm/vulnerable-pkg@1.0.0" || !update.Matched {
		t.Fatalf("unexpected update %#v", update)
	}
	if len(update.Licenses) != 0 || update.Scorecard != nil {
		t.Fatalf("update must carry only the mutated fields, got %#v", update)
	}
	if len(update.Vulnerabilities) != 1 || update.Vulnerabilities[0].ID != "OSV-2024-0001" {
		t.Fatalf("unexpected vulnerabilities %#v", update.Vulnerabilities)
	}

	// The matcher must not have enriched the request registry in delta mode.
	if got := len(deltaRegistry.All()); got != 0 {
		t.Fatalf("delta path mutated request registry: %d packages", got)
	}

	merged := sdk.ApplyPackageUpdates(deltaRegistry, delta.PackageUpdates)
	if diff := registryDiff(legacy.Registry, merged); diff != "" {
		t.Fatalf("merged delta registry differs from legacy registry: %s", diff)
	}
	if legacy.MatcherStats != delta.MatcherStats {
		t.Fatalf("matcher stats diverge: legacy %#v, delta %#v", legacy.MatcherStats, delta.MatcherStats)
	}
}

// registryDiff deep-compares two registries package by package.
func registryDiff(want, got *sdk.PackageRegistry) string {
	wantPkgs := want.All()
	gotPkgs := got.All()
	if len(wantPkgs) != len(gotPkgs) {
		return fmt.Sprintf("package count %d != %d", len(gotPkgs), len(wantPkgs))
	}
	for _, wantPkg := range wantPkgs {
		gotPkg, ok := got.Get(wantPkg.PURL)
		if !ok {
			return fmt.Sprintf("missing package %s", wantPkg.PURL)
		}
		if !reflect.DeepEqual(wantPkg, gotPkg) {
			return fmt.Sprintf("package %s differs: want %#v, got %#v", wantPkg.PURL, wantPkg, gotPkg)
		}
	}
	return ""
}

// TestConformance runs the SDK conformance suite against the module,
// including the bomly-plugin.json identity cross-check.
func TestConformance(t *testing.T) {
	conformance.Test(t, conformance.Config{
		Module:       Module(),
		ManifestPath: filepath.Join("..", "bomly-plugin.json"),
		SampleConfig: json.RawMessage(`{"api_base":"https://api.osv.dev","cache_ttl":"24h","disable_kev":false}`),
	})
}

// TestProbeBinary builds the real plugin binary and probes it over the
// managed HashiCorp gRPC transport, asserting the served descriptor equals
// the in-process one.
func TestProbeBinary(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not available; skipping managed-transport probe")
	}
	binaryPath := filepath.Join(t.TempDir(), "bomly-plugin-osv-matcher")
	build := exec.Command(goBinary, "build", "-o", binaryPath, "./cmd/bomly-plugin-osv-matcher")
	build.Dir = ".."
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build plugin binary: %v\n%s", err, output)
	}
	conformance.ProbeBinary(t, binaryPath, conformance.WithModule(Module()))
}
