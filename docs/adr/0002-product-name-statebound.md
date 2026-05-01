# ADR 0002: Product name "Statebound" (working name, trademark pending)

- Status: Accepted (working name pending trademark clearance)
- Date: 2026-05-01

## Context

The project was previously developed under a different working name.
Three concerns drove a rename before any public-facing artifact was
produced:

1. **Trademark proximity.** The prior mark sits close to existing
   identity and access products in the same buyer segment. A formal
   trademark search would likely surface collision risk in the same
   Nice classes that an authorization governance product needs to
   register in.
2. **Phonetic and semantic confusion with OpenSLO.** OpenSLO is an
   established specification project. A name that reads or sounds
   similar invites confusion in search, conference talks, and
   community discussion, and complicates SEO.
3. **Weak inherent distinctiveness.** The "Open-" prefix plus a short
   acronym is descriptive and crowded. A more distinctive,
   suggestive mark improves both legal defensibility and brand
   recognition.

"Statebound" was selected because it is suggestive (not descriptive)
of the desired-state positioning, short, easy to pronounce and spell,
and — based on preliminary search — does not collide with established
marks in the relevant Nice classes. Formal attorney clearance has not
yet been completed.

Reference: CLAUDE.md preamble ("Changelog vs v2.1").

## Decision

1. Adopt **Statebound** as the in-repo working name immediately. All
   internal references — package paths, module names, CLI binaries,
   schemas, ADRs, docs, examples — use "Statebound" / `statebound`
   from this point forward.
2. **Defer all public-facing use** until formal attorney trademark
   clearance is confirmed. "Public-facing" includes:
   - The GitHub repository name and visibility.
   - Any registered domain.
   - Any social media handle, mailing list, or community channel.
   - The README, marketing pages, or release notes of any public
     repository.
3. The README of this repository carries a prominent banner stating
   that the name is the working name and not yet cleared.
4. Once clearance is confirmed, this ADR is updated to record the
   confirmation and remove the "pending" qualifier from Status.
5. If clearance is denied, this ADR is superseded by a follow-up ADR
   documenting the replacement mark and the rename steps.

## Consequences

### Positive

- The mark is clearer, more distinctive, and aligns with the product
  positioning ("desired-state" / "bound to declared state"). This
  helps both legal defensibility and product narrative.
- Collision risk with established marks in the buyer segment, and
  with the OpenSLO specification project, is materially lower than
  the prior mark.
- Choosing the name early — before any public surface exists —
  minimizes the migration cost if the mark must change again.

### Negative

- Until clearance lands, the project cannot be publicized. Recruiting,
  community building, and partner conversations are constrained.
- Search and discovery friction during the gap: people who hear about
  the project informally may not be able to find it.
- Existing notes, drafts, and internal communications under the old
  working name need migration. This is mostly bookkeeping but it is
  not free.
- A clearance denial would force a second rename, which is more
  expensive than this one because internal artifacts now exist.

## References

- CLAUDE.md preamble, "Changelog vs v2.1" (the rename rationale).
- ADR 0001 (reasoning-as-addon), which is unaffected by the rename.
