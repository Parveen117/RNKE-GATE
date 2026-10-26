# Canonical repository governance

The canonical repository is https://github.com/Parveen117/RNKE-GATE.
The repository owner, **@Parveen117**, controls acceptance of changes and publication of releases.

## Changes and review

- External suggestions may be submitted through issues or pull requests. Submission does not grant write access or permission to merge.
- Only the owner, or an integration explicitly authorized by the owner, may update the canonical repository. Do not add other write collaborators without the owner's explicit authorization.
- A fork, copied repository, or modified certificate is a separate work; it is not an owner-approved canonical release merely because it shares a name or history.
- Preserve prior authors, contributors, source citations, licenses, notices and claim boundaries. This governance policy does not change copyright ownership or existing reuse permissions.
- Keep release tags, archived files and dated provenance snapshots unchanged. Publish corrections in a new commit and a new version, linking the earlier record.

## Enforcement

`.github/CODEOWNERS` routes review requests; it does not itself remove write access or protect branches.
Actual enforcement is through GitHub collaborator permissions, branch/tag rules and release immutability.
The target configuration is owner-controlled writes, blocked force pushes/deletions, and immutable new releases.
Audit authorized Apps, deploy keys and Actions permissions as well as human collaborators; keep the Zenodo archival integration working.

## Citation and evidence

Use [RESEARCH_PROVENANCE.md](RESEARCH_PROVENANCE.md) for the dated content record and the exact archived versions.
An archive timestamp helps document availability of particular content. It does not by itself establish novelty, a universal result, or patent priority.
