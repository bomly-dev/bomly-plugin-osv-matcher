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
`~/.bomly/cache/osv-vulns`, and `~/.bomly/cache/kev`). Cache failures are
non-fatal: the matcher logs a warning and continues without caching.

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
