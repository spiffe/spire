# Supported Operating Systems

SPIRE Server and Agent run on a number of operating systems. This document
details the official project support stance for each of them.

## Officially supported

The SPIRE project officially supports **Linux** and **Windows**. These are the
platforms we build and publish release artifacts for, and the platforms we
exercise in CI with both unit and integration tests on every pull request.
Bugs reported against these platforms are treated as bugs in SPIRE and are
addressed by the maintainers.

## Supported for development

Other operating systems, such as **macOS**, are supported for development
purposes. SPIRE is expected to build and the unit test suite is expected to
pass there, and macOS is exercised in CI to that extent. SPIRE may well work
on these platforms beyond that, but the project makes no guarantees about
stability or functional completeness, and does not run integration tests on
them. Issues that only reproduce on these platforms are handled on a
best-effort basis.

Platforms that are neither officially supported nor listed above may still
work, but they receive no project attention at all.

Note that individual plugins may have narrower platform support than SPIRE
itself, even on officially supported operating systems. See the documentation
for the plugin in question.

## Becoming officially supported

The project is open to adding operating systems to the officially supported
list. Support is a maintenance commitment rather than a one-time change, so
the following are required:

1. **The platform must have built-in node and workload attestors.** SPIRE is
   not meaningfully usable on a platform it cannot attest, so a platform
   cannot be officially supported until it has both node attestor and workload
   attestor implementations in-tree that work on it. Existing plugins that are
   already platform agnostic can satisfy this.
2. **The platform must be testable in CI.** We need to be able to run the
   integration test suite on the platform as part of the normal pull request
   workflow. In practice this means a runner for the platform must be
   available to the project's CI, and the test suite must be made to work
   there.
3. **The community must help maintain it.** Someone needs to be responsible
   for keeping the platform working over time: investigating failures specific
   to it, fixing platform-specific bugs, and keeping its CI jobs healthy.
   Maintainers cannot take this on for platforms they do not run.
