package plugin

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/bomly-dev/bomly-sdk"
)

// Name is the plugin's identity. It MUST equal the "id" field in
// bomly-plugin.json — Bomly refuses to load a plugin whose manifest id and
// runtime descriptor name disagree. It is also the descriptor name the Bomly
// CLI composition keys on when it embeds this matcher.
const Name = "osv"

// displayName is the human-readable matcher name.
const displayName = "OSV"

// moduleConfig is the JSON configuration accepted in managed execution under
// plugins.matchers.osv. Durations are Go duration strings ("24h", "30m").
type moduleConfig struct {
	APIBase            string `json:"api_base"`
	CacheDir           string `json:"cache_dir"`
	CacheTTL           string `json:"cache_ttl"`
	BypassCache        bool   `json:"bypass_cache"`
	DisableKEV         bool   `json:"disable_kev"`
	KEVCacheDir        string `json:"kev_cache_dir"`
	KEVCacheTTL        string `json:"kev_cache_ttl"`
	VulnDetailCacheDir string `json:"vuln_detail_cache_dir"`
	VulnDetailCacheTTL string `json:"vuln_detail_cache_ttl"`
}

// moduleDescriptor is the matcher's static registration data, shared by the
// embedded Descriptor method and the managed Module constructor.
func moduleDescriptor() sdk.MatcherDescriptor {
	descriptor := (&Matcher{}).Descriptor()
	descriptor.ConfigSchema = sdk.MustConfigSchemaFor(moduleConfig{})
	return descriptor
}

// configFromHost builds the matcher Config from the host-provided JSON block.
func configFromHost(host sdk.HostContext) (Config, error) {
	var raw moduleConfig
	if err := host.DecodeConfig(&raw); err != nil {
		return Config{}, fmt.Errorf("decode osv matcher configuration: %w", err)
	}
	cfg := DefaultConfig()
	cfg.Logger = host.Logger()
	cfg.HTTPClientProvider = host.HTTPClient()
	if strings.TrimSpace(raw.APIBase) != "" {
		cfg.APIBase = raw.APIBase
	}
	if strings.TrimSpace(raw.CacheDir) != "" {
		cfg.CacheDir = raw.CacheDir
	}
	if strings.TrimSpace(raw.KEVCacheDir) != "" {
		cfg.KEVCacheDir = raw.KEVCacheDir
	}
	if strings.TrimSpace(raw.VulnDetailCacheDir) != "" {
		cfg.VulnDetailCacheDir = raw.VulnDetailCacheDir
	}
	cfg.BypassCache = raw.BypassCache
	cfg.EnableKEV = !raw.DisableKEV
	var err error
	if cfg.CacheTTL, err = parseOptionalDuration(raw.CacheTTL, cfg.CacheTTL); err != nil {
		return Config{}, fmt.Errorf("invalid cache_ttl: %w", err)
	}
	if cfg.KEVCacheTTL, err = parseOptionalDuration(raw.KEVCacheTTL, cfg.KEVCacheTTL); err != nil {
		return Config{}, fmt.Errorf("invalid kev_cache_ttl: %w", err)
	}
	if cfg.VulnDetailCacheTTL, err = parseOptionalDuration(raw.VulnDetailCacheTTL, cfg.VulnDetailCacheTTL); err != nil {
		return Config{}, fmt.Errorf("invalid vuln_detail_cache_ttl: %w", err)
	}
	return cfg, nil
}

func parseOptionalDuration(value string, fallback time.Duration) (time.Duration, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(trimmed)
	if err != nil {
		return 0, err
	}
	if parsed <= 0 {
		return fallback, nil
	}
	return parsed, nil
}

// Module packages the matcher for both execution modes: Bomly can embed it
// in-process or serve it as a managed plugin subprocess (see
// cmd/bomly-plugin-osv-matcher).
func Module() sdk.Module {
	return sdk.Module{
		Kind: sdk.PluginKindMatcher,
		Matcher: &sdk.MatcherModule{
			Descriptor: moduleDescriptor(),
			New: func(_ context.Context, host sdk.HostContext) (sdk.Matcher, error) {
				cfg, err := configFromHost(host)
				if err != nil {
					return nil, err
				}
				return New(cfg)
			},
		},
	}
}
