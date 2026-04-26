# kernel-diffguard

kernel-diffguard is a new public project for analyzing git repositories for security and operational risk, using the Linux kernel as the prime initial example.

The project is intentionally broader than the kernel: the kernel gives us a large, high-stakes, public, mailing-list-driven repository where we can build and validate reusable workflows for other git histories.

## Core questions

1. Was a malicious change added to the code, possibly over multiple commits, by:
   - an untrusted developer,
   - a trusted but compromised developer, or
   - injection into the git tree or generated binaries outside ordinary commits?
2. If a system updates from commit X to commit Y, where Y = X + n and n >= 1:
   - what changed that can affect our system,
   - what needs to be re-tested,
   - which commits are obviously correct versus too complex to trust casually, and
   - can mailing-list discussion or review context help us reason about the patch?

## Initial direction

The first milestone is not an all-knowing AI reviewer. It is a reproducible analysis workbench that gathers evidence, reduces it deterministically, and makes human review sharper:

- ingest commit ranges and associated metadata,
- classify touched subsystems and likely runtime impact,
- surface suspicious provenance, authorship, and review patterns,
- correlate patches with public discussion, especially Linux kernel mailing lists,
- compare source trees and generated artifacts where possible, and
- emit review packets that separate facts, heuristics, uncertainty, and recommendations.

## Trust posture

Repository contents, commit metadata, mailing-list text, build logs, generated artifacts, and binaries are all treated as hostile input. The project should prefer deterministic parsing and reduction first, then carefully bounded model-assisted analysis over selected artifacts.

## Status

Fresh project skeleton. See `docs/architecture.md` and `docs/roadmap.md` for the starting design.
