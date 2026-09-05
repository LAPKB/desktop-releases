# LAPKB desktop releases

This repository is the public home for LAPKB desktop release metadata and, once
published, immutable signed update assets. It contains no application source.

`channels/stable.json` and `channels/beta.json` are v1 routing catalogs for the
currently published desktop applications. Their `manifestUrl` values stay
`null` until a real, signed Tauri updater manifest is published. A non-null URL
must point to the standard Tauri updater document; this catalog does not define
a second artifact format and never carries updater public keys or trusted launch
metadata. The public source-manifest schema also requires an explicit
`accessPolicy`. Trusted build tooling accepts any explicitly public app; a
protected app must use a valid role key exactly matching its logical ID, with
protected roles unique across the compiled catalog. This policy is compiled
into Launcher and is never read from these remote update catalogs.

Publish in this order: immutable signed assets, the per-app Tauri manifest, then
the suite catalog. Validate locally with:

```sh
npm ci
npm test
```
