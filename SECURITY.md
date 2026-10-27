# Security policy

## Supported versions

The latest release is supported with security fixes. Older releases are not.

## Reporting

Please do not open a public issue for a vulnerability. Use GitHub's private
vulnerability reporting ("Security" → "Report a vulnerability") on this repository,
or email the maintainer listed in `git log`.

Include: the version, the command line used, a description of the impact and, if
possible, a reproducer. Reports about the *scanning* behaviour against third-party
systems are out of scope; see the legal section of the README.

## Scope

`0800` parses hostile network input by design. Bugs in the SMB2, NDR, BER, XDR,
MySQL, PostgreSQL or Redis decoders (out-of-bounds reads, panics, unbounded
allocations) are in scope and get priority. The parsers are fuzzed in CI.

The tool is read-only: it never writes, renames or deletes remote data. Any code
path that mutates a remote filesystem is a security bug.
