# Redact what geiger found

Once you have rotated (or decided to rotate) what a scan turned up, geiger can
strip the values from the files it read. A backup directory or an old dotfile then
stops leaking the same credentials again.

```sh
geiger --dangerous-redact ~/.claude                    # plan only: what would change
geiger --dangerous-redact --confirm-redact ~/.claude   # rewrite in place
geiger --dangerous-redact --confirm-redact --git-history \
       --redact-replacements /tmp/repl.txt ./repo      # + file for git filter-repo
git filter-repo --replace-text /tmp/repl.txt           # then scrub the history
```

## The plan

The plan lists each file, and under it each value: the line it sits on, the module
that recognized it, the variable or JSON path it came from, a masked tail to match
against the findings report, and the form it was found in. The same list is
printed after a rewrite, as the record of what changed.

## What gets rewritten

A plain or JSON-escaped value is a text swap. The file keeps its shape and only
the value changes.

A value stored as base64 (a docker `auth` blob, a kubeconfig key) is replaced too,
but the placeholder does not decode. The consumer of that file then errors until
the value is replaced.

Anything else is listed under a warning with the reason and is not rewritten:

- git history blobs (use the replacements file)
- archive members
- symlinks
- binary and SQLite stores
- values harvested from a secrets store
- values that were transformed before geiger saw them

## Two things it will not do

It keeps no backup. A backup would hold the secrets again.

It revokes nothing. A redacted file stops re-leaking; it is not a rotated
credential.

It refuses to run on stdin, `--env`, `--metadata`, `--browser`, or a scanner
report, because none of those is a file it read itself.
