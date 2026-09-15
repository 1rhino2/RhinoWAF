# The detection engine and rule format

RhinoWAF's detection engine reads a set of rules, runs them against each
request (and optionally the response), and adds up an anomaly score. When the
score crosses the threshold, or a block-action rule fires, the request is
blocked with a page that says which rules matched.

The default rules are embedded in the binary, so a fresh install works with no
config. You can replace them or layer your own on top.

## Rule files

Rules live in `*.rules` files, a line-oriented format with `#` comments. A rule
is a block:

```
rule 942100 "SQL injection" {
    category   sqli
    severity   critical          # notice | warning | error | critical
    paranoia   1                 # 1-4, higher = more aggressive, more noise
    phase      request-body      # request-headers | request-body | response-headers | response-body
    targets    args, cookies, json, path
    transforms urldecode, nulls
    skip       opaque            # skip jwt/base64 blobs
    op         sqli
    action     score             # score | block | log | allow | challenge
    mode       block             # block | detect (detect never blocks, just logs)
    tags       owasp:A03, cwe:89
}
```

`op` takes the operator name and the rest of the line as its argument, so a
regex needs no escaping:

```
rule 931130 "RFI with an IP host" {
    category rfi   severity critical
    targets args   transforms urldecode, lower
    op rx (?:ftps?|https?)://(?:\d{1,3}\.){3}\d{1,3}
    cond { targets args  op !contains example.com }   # all conds must match
}
```

`@data/list.txt` loads a pattern list (one per line) for the `pm` and
`shellcmd` operators. Duplicate rule ids across files are a load error.

### Targets

`args`, `args_names`, `path`, `query`, `cookies`, `cookie_names`,
`headers[name]`, `header_names`, `body`, `json`, `json_names`, `xml`,
`files_names`, `files_content`, `ua`, `referer`, `host`, `method`,
`content_type`, and the response side `resp_status`, `resp_headers`,
`resp_body`. `headers[user-agent]` targets one header; `args[q]` one argument;
a trailing `*` globs a name prefix.

### Transforms

Applied in order before the operator sees the value. Each is a single pass and
none calls another, so the chain is exactly what you wrote. Double decoding is
explicit (`urldecode, urldecode`).

`lowercase`, `urldecode`, `urldecode_uni` (IIS `%uXXXX` + fullwidth folding),
`htmldecode`, `jsdecode`, `cssdecode`, `utf8normalize`, `nulls`, `compress_ws`,
`remove_ws`, `remove_comments`, `remove_comments_char`, `base64decode`,
`hexdecode`, `normalize_path`, `normalize_path_win`, `trim`, `cmdline`.

### Operators

- Matching: `contains`, `containsword`, `beginswith`, `endswith`, `streq`,
  `within`, `rx` (Go RE2, linear time so no ReDoS; no backreferences, use
  `cond` chains instead), `pm` (Aho-Corasick over a pattern list).
- Numeric: `eq`, `gt`, `lt`, `ge`, `le`, `len`.
- Detectors: `sqli`, `xss`, `detectpath`, `detectxxe`, `shellcmd @list`,
  `ssrfhost`, `jndi`, `byterange`, `validutf8`, `unconditional`.

Prefix an op with `!` to negate it.

## Anomaly scoring

Severity is the default score (notice 2, warning 3, error 4, critical 5). A
rule's matches are scored per target label (`args:q`, `cookies:session`,
`json:user.name`), and the request score is the highest label total plus a
small bump for other labels that also scored. That is the difference from plain
CRS: one long legitimate value that trips three notice rules totals 2, not 6,
so it does not false-positive, while a real attack sprayed across arguments
still adds up and blocks. Set `engine.scoring_mode` to `sum` for classic CRS
behaviour.

`action block` rules (scanner UAs, shellshock, log4shell) block on their own
regardless of score. `action allow` stops evaluation and lets the request
through, with evidence naming the allow rule, so whitelists are explainable
too.

## Paranoia levels

Level 1 is the default: high-confidence rules, very few false positives. Higher
levels add rules that catch more but flag more borderline input. Set the level
globally (`engine.paranoia`), per path, or per vhost. A site can also raise the
level for one path prefix and leave the rest alone.

## Tuning: exclusions and overrides

Runtime tuning goes in `config/rules.d/*.rules`, layered on top of the defaults:

```
disable  920350                                   # turn a rule off
override 941100 { paranoia 2  score 3 }           # change its level or weight
exclude {                                          # carve out an endpoint
    rules   942100, 942190
    path    /api/search*
    methods POST
    targets args[q]
}
```

Per-vhost tuning goes in the `engine` block of a `backends.json` entry
(paranoia, threshold, mode, disabled_rules, exclusions, per-path overrides).

## Detect mode

Set `engine.mode` to `detect` (globally, per path, or per vhost) to log and
score without blocking. Useful for watching a new site for a day before turning
on enforcement. Detected requests carry an `X-WAF-Detect` header with the rule
ids when `explain_on_block` is not `none`.

## Reading a block

Every block writes a line to `logs/engine.log` (JSON) and a short line to the
main log:

```
[ENGINE] BLOCK 203.0.113.9 GET /search score=7/5 pl=1 top=args:q rules=942100,942190 req=ab12
```

The block page shows the request id, the matched categories, and the rule ids
(controlled by `engine.explain_on_block`: `none`, `rules`, or `full`).

## Note on rule ids

The ids use CRS-style family prefixes (`942xxx` for SQLi, `941xxx` for XSS) so
the family is recognizable, but they are RhinoWAF's own ids, not CRS rule ids.
Do not paste CRS exclusion ids here and expect them to match.

## Validating changes

`rhinowaf -check-rules` compiles the config and the ruleset, prints the result,
and exits non-zero on any error, like `nginx -t`. Run it before a reload.
