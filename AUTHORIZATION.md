# Upstream authorization record — Covenant Eyes materials in this build

Per the project owner (2026-10-11): **written authorization from the Covenant Eyes
head of software engineering** grants this project use of Covenant Eyes' classifier
model (the `b1`/`b2`/`b3` ensemble shards and supporting bundle data) and CE
logos/branding assets in this Linux build, without a clean-room requirement — the
stated goal is a first-party-quality Linux build of the product.

Consequences for this repository:

- `crates/lustless-classifier/` loads CE's production classifier bundles
  (`re/samples/data/enc/*.dat.enc`, decrypted via the documented scheme in
  `re/findings/10-classifier/bundle-formats.md` §1) instead of a third-party model.
- CE logos/icons extracted from the shipped binaries may be used in the tray,
  dashboard, and package branding (`packaging/assets/`).
- The recovered decryption keys in `re/findings/10-classifier/bundle-formats.md`
  are implementation details of this integration.

**Requirement:** the written authorization itself MUST be kept with the project
records and referenced here (document identifier / date / signatory) before any
public release of a build containing CE materials.
