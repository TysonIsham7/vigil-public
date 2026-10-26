# publish-public

Publish one sanitized commit from a private git repository to its public mirror.
The script is repo-agnostic: each repository supplies its own `.publish-public.yml`.
It is MIT licensed. It does not vendor third-party source. The only downloaded
program is the official gitleaks release named in `checksums/`, and that tarball
is checksum-verified before it runs.

The private repository is never rewritten. Nothing is pushed unless you pass
`--push`. A push is a normal fast-forward of one new commit, not a force push.

## Run

From the private repo, with bash (macOS ships bash 3.2; that is enough):

```bash
cp tools/publish-public/examples/denylist.example .publish-public.denylist
# optional: real team IDs, host names, and addresses
cp tools/publish-public/examples/local.yml.example .publish-public.local.yml

bash tools/publish-public/publish.sh
bash tools/publish-public/publish.sh --ref HEAD --push
```

The default is a dry run. It prints a report and a diff summary against the
public branch. Add `--report path` to also write the report. `--keep` leaves
the temp tree. `--repo` and `--config` point at another checkout.

Apple Silicon downloads `gitleaks_*_darwin_arm64.tar.gz`. Intel Macs download
the darwin x64 archive. Linux x64 and arm64 are pinned too. The cache is
`$XDG_CACHE_HOME/publish-public` or `~/.cache/publish-public`.

Create `.publish-public.denylist` first. If that file is missing, the run
stops and nothing is pushed. `.gitignore` in this repo ignores the denylist
and `.publish-public.local.yml`.

## Config

`.publish-public.yml` lists:

- `public_remote` and `public_branch`
- `author_name` and `author_email` for the published commit
- `drop` paths (files, directories, and `*` / `**` globs)
- `replacements`: `from` (literal) or `pattern` (extended regular expression), `to`, optional `skip_if_match`, `paths`, and `skip_paths`
- `denylist` (default `.publish-public.denylist`)
- `denylist_allow` globs for fixture paths that intentionally contain fake tokens
- `gitleaks_config` when the repo has one

`.publish-public.local.yml` is merged when it exists. Put real literals there
so the committed config does not become a copy of the secrets. Sentinels such
as `REPLACE_APPLE_TEAM_ID` show the shape for a team ID, bundle ID, Mac
hostname, username, home path, email, device model, and business name.

Samples:

- `examples/vigil.publish-public.yml` (this repo; also copied to `/.publish-public.yml`)
- `examples/tailremote.publish-public.yml` (Swift/Xcode signing, bundle IDs, team ID)

Built-in drops always remove the denylist, the local overlay, env files other
than `.env.example`, `xcuserdata`, provisioning profiles, `.p12`, `.pfx`, `.p8`,
and common private-key filenames. Set `builtin_drops: false` to skip the
env and signing drops. The denylist file is still removed.

## What the scan catches

The scan runs after drops and replacements, on the temp tree and on the commit
message. Any hit is a hard failure. The public remote is not updated. Output
is `file:line: rule matched` plus a masked value. The raw match is not printed.
A failed commit message is withheld from the report.

1. **Denylist.** Exact strings and `regex` lines from the gitignored file.
   `COMMIT_MESSAGE` is the path when the message itself matches.
2. **Author name in code.** Tokens come from `author_name` (the full name and
   each word of 3 or more letters) unless `name_tokens` is set. A case-insensitive
   substring match in source fails. `LICENSE`, `COPYING`, and `LICENCE` may
   name the copyright holder. Markdown and the YAML config are not source.
   The configured GitHub noreply address is not a source file.
3. **gitleaks 8.30.1.** Default rules, plus `.gitleaks.toml` when configured.
   The same scan covers the commit message. The checksum file is
   `checksums/gitleaks-8.30.1.sha256`.

Replacements for team IDs, bundle IDs, home directories, emails, and device
models run first, so a value that was rewritten to a placeholder is not a hit.
A value the replacement missed still fails.

## Author

Published commits use the name and email in the config. For Vigil that is
Tyson Isham and `131544016+TysonIsham7@users.noreply.github.com`. The name may
appear in a LICENSE copyright line. It must not appear in code.

## Tests

```bash
bash tools/publish-public/tests/run.sh
```

The tests cover denylist hits, a gitleaks hit, a name in a Swift file, a
commit-message hit, a clean push to a local bare repo, and the guarantee that
a failed scan does not push. They do not contact the public Vigil mirror
except for the final dry run, which only reads it.
