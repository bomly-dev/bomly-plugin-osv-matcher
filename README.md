# bomly-plugin-osv-matcher

OSV vulnerability matcher for [Bomly](https://github.com/bomly-dev/bomly-cli).

It enriches packages in a Bomly scan with vulnerability data from
[OSV.dev](https://osv.dev), then flags vulnerabilities listed in the
[CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
as actively exploited.

> **Already inside the Bomly CLI.** This matcher ships embedded in the `bomly`
> binary as the built-in `osv` matcher — you do not need to install this plugin
> to use OSV enrichment. This repository is the matcher's home as a standalone
> module: the Bomly CLI consumes the same code in-process, and the plugin
> binary serves it to hosts that run matchers as managed subprocesses.

## Identity

- Plugin id / descriptor name: `osv`
- Kind: matcher
- Module path: `github.com/bomly-dev/bomly-plugin-osv-matcher`

## Network behavior

This matcher performs network calls **only during enrichment** (`bomly scan
--enrich`), never during audit-only runs:

- `https://api.osv.dev` — batch vulnerability queries and per-vulnerability
  detail records.
- `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
  — the KEV catalog (skippable with `disable_kev`).

Responses are cached on disk (default `~/.bomly/cache/osv`,
`~/.bomly/cache/osv-vulns`, and `~/.bomly/cache/kev`). The package-level
cache directory must be creatable, or the matcher fails to start; if the
detail or KEV cache directory cannot be created, the matcher runs without that
cache. A failed cache write is non-fatal: the matcher continues, counting failed
package and detail cache writes in its debug summary; a failed KEV cache write
is not reported.

## Access

`bomly-plugin.json` declares what the matcher touches, which Bomly shows when you install it and in `bomly plugin info`. It is a disclosure, not a sandbox.

| Access | Why |
| --- | --- |
| Reads and writes `home` | The response caches, `~/.bomly/cache/osv`, `~/.bomly/cache/osv-vulns` and `~/.bomly/cache/kev` by default |
| Network `api.osv.dev` | The OSV API: batch queries and per-vulnerability records |
| Network `www.cisa.gov` | The CISA KEV catalog, unless `disable_kev` is set |
| Environment `HOME`, `USERPROFILE` | `os.UserHomeDir` reads `HOME` (`USERPROFILE` on Windows) to locate the default caches |

Setting `api_base` or the cache directories moves the API or the caches to a place you chose; the declaration describes the defaults. If Bomly cannot find your home directory, the caches fall back to `.bomly-cache/` in the directory Bomly runs in, which the access block does not cover ([bomly-planning#115](https://github.com/bomly-dev/bomly-planning/issues/115)). The matcher needs no particular pipeline input beyond the packages it is asked to match, so it declares no requirements.

## Configuration

Embedded execution is configured through the Bomly CLI's own `osv` settings.
Managed execution reads a JSON block under `plugins.matchers.osv`:

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `api_base` | string | `https://api.osv.dev` | OSV API base URL |
| `cache_dir` | string | `~/.bomly/cache/osv` | Package-level result cache |
| `cache_ttl` | duration string | `24h` | Package-level cache TTL |
| `bypass_cache` | bool | `false` | Always fetch fresh results |
| `disable_kev` | bool | `false` | Skip the KEV enrichment pass |
| `kev_cache_dir` | string | `~/.bomly/cache/kev` | KEV catalog cache |
| `kev_cache_ttl` | duration string | `6h` | KEV catalog cache TTL |
| `vuln_detail_cache_dir` | string | `~/.bomly/cache/osv-vulns` | Per-vulnerability detail cache |
| `vuln_detail_cache_ttl` | duration string | `168h` | Detail cache TTL |

## Package-updates delta protocol

The matcher advertises `package-updates-v1`. When the host sets
`AcceptPackageUpdates`, `Match` leaves the request registry untouched and
returns one delta per enriched package (PURL, `Matched`, and the vulnerability
list). This is safe because every registry mutation the legacy in-place path
performs is expressible through `Package.MergeFrom`: vulnerabilities are
unioned by `(Source, ID)` and `Matched` is ORed in. The equivalence is pinned
by `TestMatchDeltaEquivalence`.

## Development

```sh
make test    # unit tests + SDK conformance suite
make build   # build bin/bomly-plugin-osv-matcher
```

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
