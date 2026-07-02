# Decision Traceability Appendix

## 1. Rule

This appendix is the mechanical index for every `D-*`, `S-*`, and `P-*` decision in
`08-decisions-and-exclusions.md`. Each decision ID MUST occur exactly once in the
first column and MUST point to at least one normative contract and one verification
location. `scripts/check_schemas.py` (or a spec-lint helper it invokes) validates
coverage, duplicate IDs, missing target documents, and IDs present in the decision
log but absent here. An implementation PR changing a decision updates its row and
the cited tests in the same change.

Section references are to this specification package.

## 2. Locked product decisions

| Decision | Normative contract | Required verification |
|---|---|---|
| D-001 | 01 G-1/G-3; 03 §§3,5 | 07 §§4.1,5,9.2 |
| D-002 | 02 §§1-2; 03 §5.3 | 07 §§3,5 |
| D-003 | 02 §2 | 07 §3.1 |
| D-004 | 02 §§1,2.2 | 07 §§3.2,E2E-3 |
| D-005 | 01 §§4-5; 03 §4 | 07 §§4.1,5,E2E-2 |
| D-006 | 01 G-4; 03 §5.5 | 07 §5 fan-out and E2E-2 |
| D-007 | 03 §§5.2-5.5 | 07 §5 ordering matrix |
| D-008 | 03 §§2.1,5.1-5.2 | 07 §§4.3,5 |
| D-009 | 03 §§3.3,5; 04 §2 | 07 §§5,6 |
| D-010 | 03 §5.6; 04 §3.1 | 07 E2E-5 |
| D-011 | 04 §§3-7 | 07 §6 |
| D-012 | 04 §9 | 07 §§6.3,6.4 |
| D-013 | 03 §§2.1,4.1 | 07 §§4.1,E2E-1 |
| D-014 | 05 §§2-3 | 07 §7 |
| D-015 | 02 §2.15; 03 §3 | 07 §§4.1,E2E-1 |
| D-016 | 01 §6; 03 §3.2 | 07 §§2,5 |
| D-017 | 05 §5 | 07 §§8,E2E-7 |
| D-018 | 03 §4.1; 05 §5.1 | 07 §8 |
| D-019 | 03 §7 | 07 §§10,E2E-8 |
| D-020 | 06 §3; 10 | 07 §§11,16 |
| D-021 | 03 §§4.2.1,5; 09 §3.3 | 07 §§4.1,4.3,E2E-5 |
| D-022 | 01 G-14/INV-14; 11 §§3-5,18; 14 §§1-10 | 07 §§2,9.7,11,E2E-9,17; 14 §11 |

## 3. Semantic clarification decisions

| Decision | Normative contract | Required verification |
|---|---|---|
| S-001 | 02 §2.1; 01 §6 | 07 §3.2 |
| S-002 | 02 §§2.2-2.3 | 07 §3.2 |
| S-003 | 02 §2.3 | 07 §3.2 |
| S-004 | 02 §2.5 | 07 §§3.2,6.4 |
| S-005 | 02 §2.6 | 07 §§3.2,6.4 |
| S-006 | 02 §§2.2,2.7 | 07 §3.2 |
| S-007 | 02 §§2.4,2.8 | 07 §3.2 |
| S-008 | 02 §§1,3 | 07 §§2,3.1 |
| S-009 | 02 §5.3; 05 §2 | 07 §§2,7 |
| S-010 | 02 §5; 04 §8 | 07 §§2,6 |
| S-011 | 02 §§2.1,2.12-2.13; 01 §6.1 | 07 §3.2 |

## 4. Ambiguity-removal and implementation decisions

| Decision | Normative contract | Required verification |
|---|---|---|
| P-001 | 05 §§2.2-2.3 | 07 §7 |
| P-002 | 03 §§2.1,4.1 | 07 §§4.1,5 |
| P-003 | 05 §6.2 | 07 E2E-6 and §14 |
| P-004 | 02 §4 | 07 §§3.2,9.4 |
| P-005 | 05 §5.1 | 07 §8 |
| P-006 | 05 §5.4 | 07 §8 |
| P-007 | 02 §5.3 | 07 §3.2 |
| P-008 | 02 §5.2; 04 §8 | 07 §6 |
| P-009 | 03 §§2.1,5.1; 09 §§2-3 | 07 §§4.3,11 |
| P-010 | 09 §4 | 07 §4.2 |
| P-011 | 09 §5 | 07 §4.2 |
| P-012 | 09 §6 | 07 §§4.3,16.2 |
| P-013 | 03 §3; 09 §7 | 07 §§4.3-4.4 |
| P-014 | 09 §5 | 07 §4.3 |
| P-015 | 09 §6 | 07 §4.2 |
| P-016 | 03 §4.6; 09 §8 | 07 §§4.3,16.1 |
| P-017 | 06 §3.1; 10 §2 | 07 §§11,16 |
| P-018 | 10 §§3-4 | 07 §§16.1-16.2 |
| P-019 | 10 §6 | 07 §16.3 |
| P-020 | 10 §§2-7 | 07 §§16.2-16.4 |
| P-021 | 05 §2.5; 10 §6 | 07 §§7,16.3 |
| P-022 | 10 §2 | 07 §16.3 |
| P-023 | 06 §3.1; 10 §8 | 07 §§11,16.1 |
| P-024 | 10 §4 | 07 §16.4 |
| P-025 | 05 §6; 10 §5 | 07 §§E2E-6,16.3 |
| P-026 | 04 §6 | 07 §§4.2-4.3,6.1 |
| P-027 | 03 §§2.1,4.5 | 07 §§4.1,11 |
| P-028 | 03 §1; 06 §3.2 | 07 §§4.2-4.3,11 |
| P-029 | 11 §2; 12 §§1-3 | 07 §9.6 |
| P-030 | 12 §§4-6 | 07 §§2,9.6 |
| P-031 | 11 §13; 12 §§3,7.3 | 07 §§9.1,9.6,E2E-4 |
| P-032 | 11 §§3,7-13 | 07 §§9.1,E2E-4 |
| P-033 | 11 §4 | 07 §§9.1,14 |
| P-034 | 11 §11; 02 §3.2 | 07 §9.1 |
| P-035 | 03 §2.1 | 07 §§4.3,5 |
| P-036 | 09 §3 | 07 §§4.3,17 |
| P-037 | 06 §5 phase 5; 12 | 07 §§9.6,17 |
| P-038 | 04 §7.4 | 07 §6.3 |
| P-039 | 03 §4.4.1 | 07 §§2,13 |
| P-040 | 11 §§2,15; 12 §§5.2,11.1 | 07 §§9.6,15 |
| P-041 | 06 §3.2; 04 §10 | 07 §§4.3,11,16 |
| P-042 | 02 §3.2; 11 §11 | 07 §§3,9.1,9.6 |
| P-043 | 06 §§1,3.2; 11 §§3,13.1,18 | 07 §§11,E2E-4 |
| P-044 | 06 §3.2; 10 §4 | 07 §§11,16 |
| P-045 | 03 §6; 06 §§1,3.2,7.2; 14 §8.4 | 07 §§4.1,9.3,9.7,E2E-9; 14 §11 |
| P-046 | 06 §§5-7; 12 §§6,13,17; 14 §§7-10 | 07 §§2,9.6-9.7,11,E2E-9,17; 14 §11 |

## 5. Review use

A changed row is not proof by itself. Reviewers follow it to the named contract and
test, confirm the behavior is still represented in executable fixtures, and require
a new decision ID when a change introduces a genuinely new choice rather than
silently overloading an existing decision.
