# Release and Branch Management

The SPIRE project maintains active support for both the current and the previous minor versions. All active development occurs in the `main` branch. Version branches are used for patch releases of the previous minor version when necessary.

## Version Branches

Each release must have its own release branch following the naming convention `release/vX.Y.Z` where `X` is the major version, `Y` is the minor version, and `Z` is patch version.

The base commit of the release branch is based on the type of release being generated:

* Patch release for older minor release series. In this case, the new release branch is based off of the previous patch release branch for the same minor release series. Example: the latest release is v1.5.z, and the release being prepared is v1.4.5. The base commit should be the `release/v1.4.4` branch.
* Security release for current minor release series. In this case, the new release branch should be based off of the previous release branch for the same minor release series. Example: the latest release is v1.5.0, and the release being prepared is v1.5.1. The base commit should be the `release/v1.5.0` branch.
* Scheduled patch release for current minor release series OR scheduled minor release. In this case, the new release branch should be based off of a commit on the `main` branch. Example: the latest release is v1.5.0, and the release being prepared is v1.5.1. The base commit should be the candidate commit selected from the `main` branch.

When a bug is discovered in the latest release that also affects releases of the prior minor version, it is necessary to backport the fix.

Once the version branch is created, the patch is either cherry picked or backported into a PR against the version branch. The version branch is maintained via the same process as the main branch, including PR approval process etc.

Ensure that the CHANGELOG is updated in both `main` and the version branch to reflect the new release.

## Releasing

The SPIRE release machinery is tag-driven. When the maintainers are ready to release, a tag is pushed referencing the release commit. While the CI/CD pipeline takes care of the rest, it is important to keep an eye on its progress. If an error is encountered during this process, the release is aborted.

The first two releases that a new maintainer performs must be performed under the supervision of maintainer that has already satisfied this requirement.

SPIRE releases are authorized by its maintainers. When doing so, they should carefully consider the proposed release commit. Is there confidence that the changes included do not represent a compatibility concern? Have the affected codepaths been sufficiently exercised, be it by automated test suite or manual testing? Is the maintainer free of general hesitation in releasing this commit, particularly with regards to safety and security? If the answer to any of these questions is "no", then do not release.

A simple majority vote is required to authorize a SPIRE release at a specific commit hash. If any maintainer feels that the result of this vote critically endangers the project or its users, they have the right to raise the matter to the SPIFFE TSC. If this occurs, the release in question MUST be frozen until the SPIFFE TSC has made a decision. Do not take this route lightly (see [General Governance](MAINTAINERS.md#general-governance)).

### Checklist

This section summarizes the steps necessary to execute a SPIRE release. Unless explicitly stated, the below steps must be executed in order.

The following steps must be completed by the primary on-call maintainer one week prior to release:

* Ensure all changes intended to be included in the release are fully merged. For the spire-api-sdk and spire-plugin-sdk repositories, ensure that all changes intended for the upcoming release are merged into the main branch from the next branch.
* Identify a specific commit as the release candidate.
* Raise an issue "Release SPIRE X.Y.Z", and include the release candidate commit hash.
* Create the release branch following the guidelines described in [Version branches](#version-branches).
* If the current state of the main branch has diverged from the candidate commit due to other changes than the ones from the CHANGELOG:
  * Make sure that the [version in the branch](pkg/common/version/version.go) has been bumped to the version that is being released and that the [upgrade integration test is updated](test/integration/suites/upgrade/README.md#maintenance).
  * Cherry-pick into the version branch the commits for all the changes that must be included in the release. Ensure the PRs for these commits all target the release milestone in GitHub.
* Create a draft pull request against the release branch with the updates to the CHANGELOG following [these guidelines](doc/changelog_guidelines.md). This allows those tracking the project to have early visibility into what will be included in the upcoming release and an opportunity to provide feedback. The release date can be set as "TBD" while it is a draft.

**If this is a major or minor release**, the following steps must be completed by the secondary on-call maintainer at least one day before releasing:

* Review and exercise all examples in spiffe.io and spire-examples repo against the release candidate hash.
* Raise a PR for every example that updates included text and configuration to reflect current state and best practice.
  * Do not merge this PR yet. It will be updated later to use the real version pin rather than the commit hash.
  * If anything unusual is encountered during this process, a comment MUST be left on the release issue describing what was observed.

The following steps must be completed by the primary on-call maintainer to perform a release:

* Mark the pull request to update the CHANGELOG as "Ready for review". Make sure that it is updated with the final release date. **At least two approvals from maintainers are required in order to be able to merge it**.
* Cut an annotated tag against the release candidate named `vX.Y.Z`, where `X.Y.Z` is the semantic version number of SPIRE.
  * The first line of the annotation should be `vX.Y.Z` followed by the CHANGELOG. **There should be a newline between the version and the CHANGELOG**. The tag should not contain the Markdown header formatting because the "#" symbol is interpreted as a comment by Git.
* Push the annotated tag to SPIRE, and watch the build to completion.
  * If the build fails, or anything unusual is encountered, abort the release.
    * Ensure that the GitHub release, container images, and release artifacts are deleted/rolled back if necessary.
* Visit the releases page on GitHub, copy the release notes, click edit and paste them back in. This works around a GitHub Markdown rendering bug that you will notice before completing this task.
* Cut new SDK releases (see [SDK Releases](#sdk-releases)).
* Open a PR targeted for the main branch with the following changes:
  * Cherry-pick of the changelog commit from the latest release so that the changelog on the main branch contains all the release notes.
  * Bump the SPIRE version to the next projected version. As for determining the next projected version, the project generally releases three patch releases per minor release cycle (e.g. `vX.Y.[0-3]`), not including dedicated security releases. The version needs to be updated in the following places:
    * Next projected version goes in [version.go](pkg/common/version/version.go)
    * Previous version should be added to upgrade integration test, following additional guidelines described in test [README.md](test/integration/suites/upgrade/README.md#maintenance)
    * Previous version should be added to [SQL Datastore migration comments](pkg/server/datastore/sqlstore/migration.go), if not already present
  * This needs to be the first commit merged following the release because the upgrade integration test will start failing on CI for all PRs until the test is brought up to date.
* Close the GitHub issue created to track the release process.
* Broadcast news of release to the community via available means: SPIFFE Slack, Twitter, etc.
* Create a new GitHub milestone for the next release, if not already created.

**If this is a major or minor release**, the following steps must be completed by the secondary on-call maintainer no later than one week after the release:

* PRs to update spiffe.io and spire-examples repo to the latest major version must be merged.
  * Ensure that the PRs have been updated to use the version tag instead of the commit sha.

### SDK Releases

SPIRE has two SDK repositories:

* [API SDK](https://github.com/spiffe/spire-api-sdk)
* [Plugin SDK](https://github.com/spiffe/spire-plugin-sdk)

SPIRE consumes these SDKs using pseudo-versions from the `next` branch in each SDK repository. This allows unreleased changes to be reviewed, merged, and consumed by SPIRE.

These SDKs need to be released with each SPIRE release.

SDK releases take place using tagged commits from the `main` branch in each repository. When cutting a new release, the `main` branch needs to be prepared with any previously unreleased changes that are part of the new release.

To create a release for an SDK, perform the following steps:

1. Review the diff between `next` and `main`.
1. Determine the commits in `next` that are missing from `main`, in other words, commits containing features that were under development that are now publicly available through the new SPIRE release (e.g. API or plugin interface additions).
1. Cherry-pick those commits, if any, into `main`.
1. Create a git tag (not annotated) with the name `vX.Y.Z`, corresponding to the SPIRE release version, for the `HEAD` commit of the main branch.
1. Push the `vX.Y.Z` tag to Github.

> [!WARNING]  
> Extra care should be taken to ensure that the tagged commit is correct before pushing. Once it has been pushed, anyone running `go get <SDK module>@latest` will cause the repository to be pulled into the Go module cache at that cache. Changing it afterwards is not without consequence.
