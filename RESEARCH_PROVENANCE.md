# Research provenance and citation

Canonical repository: **[Parveen117/RNKE-GATE](https://github.com/Parveen117/RNKE-GATE)**. Maintainer: **@Parveen117**.
For author and contributor credit, retain the repository's citation metadata and the credits in the specific work being cited.

## Dated content record

Recorded on **2026-10-26 (UTC)**, before this provenance update:

- Default branch: `main`.
- Exact baseline commit: [`206af48cae62dc39966f92e17c87d66d4a18d6f2`](https://github.com/Parveen117/RNKE-GATE/commit/206af48cae62dc39966f92e17c87d66d4a18d6f2).
- Git tree: `36ad3a02162e6386dbcdd2225f08eb094e859fef`.
- Inventory: **21 tracked entries**, including SHA-256 hashes of every Git blob's bytes.
- [Machine-readable snapshot](provenance/2026-10-26/baseline.json) · [Snapshot checksum](provenance/2026-10-26/baseline.sha256).

This is a content snapshot taken today, not a backdated first-disclosure claim.
Git object IDs and SHA-256 file digests are recorded separately. Gitlinks, if present, identify submodule commits; their external contents are not included.

## Archived version

Verified record metadata: [10.5281/zenodo.22143545](https://zenodo.org/records/22143545), version `v1.1`, record created `2026-08-28T11:31:45.264382+00:00`.

Recorded release commit: `206af48cae62dc39966f92e17c87d66d4a18d6f2`. Archive byte verification: **verified** (details and archive SHA-256 in the snapshot).

The record DOI identifies this version. The concept DOI, `10.5281/zenodo.22143544`, groups versions and should not replace an exact-version citation.

The snapshot records the published GitHub releases observed during this audit. Existing root citation metadata can describe an older release: cite the exact artifact, tag, commit and version DOI used.
The live branch may contain work added after the archive. A prior DOI does not timestamp those additions.

## Verify without running research code

From a clone that contains the baseline commit:

```bash
python provenance/verify_snapshot.py --repo . --snapshot provenance/2026-10-26/baseline.json
```

If a shallow clone lacks the baseline, fetch that exact commit first. The verifier reads Git objects, checks the manifest checksum, tree identity, file inventory and each blob's SHA-256. It does not execute experiments or validate scientific claims.
The checksum file is an integrity check; independent anchoring requires a dated external archive or timestamp receipt.

## New result → new evidence record

1. State the exact result, assumptions, limitations, reproduction command and relevant file paths.
2. Record the commit and content hashes, preserve raw observations and record any independent review separately.
3. Check citation metadata, rights notices and release contents. Where both files exist, Zenodo uses `.zenodo.json` rather than `CITATION.cff` for archival metadata.
4. Create a new release at that commit after the repository's existing release gates pass. Do not move a published tag to new content.
5. Verify the Zenodo record, exact version DOI, creation time and archive bytes; record the receipt in a later additive commit.

See [governance](GOVERNANCE.md) for owner-controlled changes and the [public research index](https://github.com/Parveen117/Publications/blob/main/PUBLIC_RESEARCH_INDEX.md) for the cross-repository record.
