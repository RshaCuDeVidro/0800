# Contributing

Thanks for taking a look. A few conventions keep the tool honest.

## Ground rules

- **Read-only.** No code path may write, rename or delete remote data. Any PR that
  adds a write primitive to `remoteFS` will be rejected.
- **Evidence first.** A finding must carry the request/response that proves it.
  If you add a detector, add the evidence strings with it.
- **No new protocol dependencies** unless there is no pure-Go alternative and the
  parser is fuzzed. The SMB client is in-tree on purpose (see the README).

## Development

```bash
make test     # go test -race ./...
make lint     # gofmt + go vet
make build    # static binary with the version from git
make shots    # regenerate docs/screenshots/*.svg
```

Go 1.24.2 or newer. Everything must build with `CGO_ENABLED=0`.

## Adding a protocol

1. Implement the wire client under `internal/<proto>` with no UI imports.
2. Expose a pure `Probe(ctx, ...)` returning a struct plus evidence.
3. Wire it into `internal/scan/probe.go` and add tags in `derive` if needed.
4. Implement `List`/`Open`/`Close` in `internal/ui/browser.go` if it is browseable.
5. Add a fake server test, and a fuzz target for every decoder that reads bytes
   from the network.

## Tests

- Unit and fake-server tests run on every push, on Linux, macOS and Windows.
- `go test -race` runs on Linux.
- Fuzzers get a 15 second smoke run in CI; run them longer locally when touching a
  parser.

## Commit style

Conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `ci:`). Keep the subject
under 72 characters.
