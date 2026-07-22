## What this changes

<!-- One or two lines. What and why. -->

## Checks

- [ ] `go test ./...`, `go vet ./...`, `gofmt -l` clean
- [ ] New/changed behaviour has a test

### If this adds or changes a module

- [ ] Recon is read-only (`GET`/`HEAD`, or a POST with `ReadOnlyPOST` and a `Note` saying why)
- [ ] `httptest`-backed test; `go run ./tools/coverage` re-run if the catalog changed
- [ ] **If the base URL is templated on a host** (`{endpoint}`, `{host}`, `{api}`,
      `{server}`): an `Endpoint` policy is declared — `saasOnly(...)` with the vendor's
      domains, or `selfHosted`. That host comes from the scanned file, so a planted value
      would otherwise aim the credential at whoever planted it. Resolve it with
      `resolveEndpoint` (which puts `--endpoint` first) and bind each host variable to the
      service it names.
