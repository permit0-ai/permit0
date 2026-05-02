# Community packs

Phase 1 placeholder. Once the federated registry and signing
infrastructure ship (Phase 2 — tracked in
[#18](https://github.com/permit0-ai/permit0/issues/18)),
community-contributed packs will live in this directory.

## Phase 1 status

- This directory is empty by design.
- `packs/permit0/<name>/` is the only path the engine loads from
  in-tree.
- Pack discovery walks both `packs/<pack>/` (legacy) and
  `packs/<owner>/<pack>/` (the new layout). The three-level shape
  `packs/community/<author>/<pack>/` is **not yet** discovered — it
  lights up when Phase 2 lands.

## Phase 2 (when this directory becomes live)

```
packs/community/
├── README.md            (this file)
├── alice/
│   └── jira/
│       ├── pack.yaml    (trust_tier: community, derived from owner)
│       └── ...
├── bob/
│   └── notion/
│       └── ...
└── ...
```

When this lands, the discovery walker will accept depth-3 layouts
under `community/`, and `permit0 pack install <owner>/<name>` will
fetch + verify lockfile signatures from the federated registry.

## Why this directory exists today

So contributors and reviewers can see exactly where Phase 2 packs
will land. Treating community packs as a first-class concept from
day one keeps the contribution UX clear: contributors who land first-
party packs (path `packs/permit0/<name>/`) follow the same layout as
contributors who'll eventually land community packs.

## Trust tier semantics

| Tier | Path | Reachable in Phase 1? |
|---|---|---|
| `built-in` | `packs/permit0/<name>/` | yes (path-derived) |
| `community` | anywhere else (default) | yes (default for non-permit0 owners) |
| `verified` | community + permit0 co-sign | no — needs signing infra |
| `experimental` | hidden by default | no — needs signing infra |

The `trust_tier:` field in `pack.yaml` is **informational only**. The
engine derives the authoritative tier from `permit0_pack`'s owner
prefix. A community pack declaring `trust_tier: built-in` does not
become built-in; the validator flags the mismatch.
