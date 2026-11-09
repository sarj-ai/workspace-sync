Use the pinned mise environment and pnpm lockfile. Keep tenant identities,
credentials, operational receipts and incident exceptions in the consuming app.
The package supports one immutable policy per process or Worker isolate.

Run `pnpm verify` before merging. Security changes need regression tests for the
affected boundary. Documentation is generated from source comments, declarations,
schemas, examples and package metadata; run `pnpm docs:generate` after changing
those inputs. Keep generated output current and preserve license notices.

The repository is public. npm publication remains disabled in package metadata.
