# SPIRE Maintainership Guidelines and Processes
This document captures the values, guidelines, and processes that the SPIRE project and its maintainers adhere to. All SPIRE maintainers, in their independent and individual capacity, agree to uphold and abide by the text contained herein.

This process can be changed, either permanently or as a one-time exception, through an 80% supermajority maintainer vote.

For a list of active SPIRE maintainers, please see the [CODEOWNERS](CODEOWNERS) file.

## General Governance
The SPIRE project abides by the same [governance procedures][1] as the SPIFFE project, and ultimately reports to the SPIFFE TSC the same way that the SPIFFE project and associated maintainers do.

TSC members do not track day-to-day activity in the SPIFFE/SPIRE projects, and this should be considered when deciding to raise issues to them. While the SPIFFE TSC has the ultimate say, in practice they are only engaged upon serious maintainer disagreement. To say that this would be unprecedented is an understatement.

### Maintainer Responsibility
SPIRE maintainers adhere to the [requirements and responsibilities][2] set forth in the SPIFFE governance document. They further pledge the following:
* To act in the best interest of the project at all times
* To ensure that project development and direction is a function of real user need
* To never take an important action in maintainer capacity with hesitation
* To fulfill the responsibilities outlined in this document and its dependents

### Number of Maintainers
The SPIRE project keeps a total of five maintainer seats. This number was chosen because 1) it results in a healthy distribution of responsibility/load given the current volume of project activity, and 2) an odd number is highly desirable for dispute resolution.

We strive to keep the number of maintainers as low as is reasonably possible, given the fact that maintainers carry powerful privileges.

This section of the document can and should be updated as the above considerations fluctuate. Changes to this section of the document fall under the same requirements as other sections. When changing this section, maintainers must re-review and agree with the document in its entirety, as other guidelines (e.g. voting requirements) will likely change as a result.

### Changes in Maintainership
SPIRE maintainers are appointed according to the [process described in the governance document][2]. Maintainers may voluntarily step down at any time. Unseating a maintainer against their will requires a unanimous vote with the exception of the unseated.

Unseating a maintainer is an extraordinary circumstance. A process to do so is necessary, but its use is not intended. Careful consideration should be made when voting in a new maintainer, particularly in validating that they pledge to uphold the terms of this document. To ensure that these decisions are not taken lightly, and to maintain long term project stability and foresight, no more than one maintainer can be involuntarily unseated in any given nine month period.

The CNCF MUST be notified of any changes in maintainership via the CNCF Service Desk.

#### Onboarding a New Maintainer
New SPIRE maintainers participate in an onboarding period during which they fulfill all code review and issue management responsibilities that are required for their role. The length of this onboarding period is variable, and is considered complete once both the existing maintainers and the to-be-appointed maintainer are comfortable. This process MUST be completed prior to the individual in question being named an official SPIRE maintainer.

The onboarding period is intended to ensure that the to-be-appointed maintainer is able/willing to take on the time requirements, familiar with SPIRE core logic and concepts, understands the overall system architecture and interactions that comprise it, and is able to work well with both the existing maintainers and the community.

## Change Review and Disagreements
The SPIRE project abides by the same [change review process][3] as the SPIFFE project, unless otherwise specified.

The exact definition/difference between "major" and "minor" changes is left to maintainer's discretion. Changes to particularly sensitive areas like the agent's cache manager, or the server's CA, are always good candidates for additional review. If in doubt, always ask for another review.

If there is a disagreement amongst maintainers over a contribution or proposal, a vote may be called in which a simple majority wins. If any maintainer feels that the result of this vote critically endangers the project or its users, they have the right to raise the matter to the SPIFFE TSC. If this occurs, the contribution or proposal in question MUST be frozen until the SPIFFE TSC has made a decision. Do not take this route lightly (see [General Governance](general-governance)).

### Experience Matters
SPIRE solves a complicated problem, and is developed and maintained by people with deep expertise. SPIRE maintainers must ensure that new features, log and error messages, documentation and naming choices, are all easily accessible by those who may not be very familiar with SPIFFE or authentication systems in general.

Decisions should favor "secure by default" and "it just works" anywhere possible, and in that order. The number of configurables should be minimized as much as possible, especially in cases where it's believed that many users would need to invoke it, or when their values (and extremes) could significantly affect SPIRE performance, reliability, or security.

A good measure is the "beginner" measure. A beginner should be able to easily and quickly understand the configurable/feature, and its potential uses/impacts. They should also be able to easily and quickly troubleshoot a problem when something important goes wrong - and not to mention, be clearly informed of such a condition!

### Review Guidelines
The SPIFFE [governance document][1], its section on [review process][3], and the SPIRE [contribution guidelines][4], must all be applied for any SPIRE review.

While reviewing, SPIRE maintainers should ask questions similar to the following:
* Do I clearly understand the use case that this change is addressing?
* Is the proposed change disruptive to other use cases that are currently supported?
* Is it possible for this change to be misconfigured? If it is, what is the impact?
* Does the proposed change adhere to the SPIRE [compatibility guarantee][5]?
* What are the failure modes? Can SPIRE keep running?
* If something goes wrong, will it be clear to the operator what it was and how to fix it?
* If this change introduces additional configurables, is it possible to replace some or all of them with a programmatic decision?

The above list is advisory, and is meant only to get the mind going.

## Release and Branch Management
The SPIRE project maintains active support for both the current and the previous major versions. All active development occurs in the `master` branch. Version branches are used for minor releases of the previous major version when necessary.

### Version Branches
When a bug is discovered in the latest release that also affects releases of the prior major version, it is necessary to backport the fix.

If it is the first time that the prior major version is receiving a backported patch, then a version branch is created to track it. The version branch is named `vX.Y` where X and Y are the two most significant digits in the semantic version number. Its base is the last tag present in master for the release in question. For example, if SPIRE is on version 0.9.3, and the last 0.8 release was 0.8.4, then a `v0.8` branch is created with its base being the master commit tagged with `v0.8.4`.

Once the version branch is created, the patch is either cherry picked or backported into a PR against the version branch. The version branch is maintained via the same process as the master branch, including PR approval process etc.

Releases for the previous major version are made directly from its version branch. Ensure that the `CHANGELOG` is updated in both the master and the version branch to reflect the new release.

### Releasing
The SPIRE release machinery is tag-driven. When the maintainers are ready to release, a tag is pushed referencing the release commit. While the CI/CD pipeline takes care of the rest, it is important to keep an eye on its progress. If an error is encountered during this process, the release is aborted.

The first two releases that a new maintainer performs must be performed under the supervision of maintainer that has already satisfied this requirement.

SPIRE releases are authorized by its maintainers. When doing so, they should carefully consider the proposed release commit. Is there confidence that the changes included do not represent a compatibility concern? Have the affected codepaths been sufficiently exercised, be it by automated test suite or manual testing? Is the maintainer free of general hesitation in releasing this commit, particularly with regards to safety and security? If the answer to any of these questions is "no", then do not release.

A simple majority vote is required to authorize a SPIRE release at a specific commit hash. If any maintainer feels that the result of this vote critically endangers the project or its users, they have the right to raise the matter to the SPIFFE TSC. If this occurs, the release in question MUST be frozen until the SPIFFE TSC has made a decision. Do not take this route lightly (see [General Governance](general-governance)).

#### Checklist
This section summarizes the steps necessary to execute a SPIRE release. Unless explicitly stated, the below steps must be executed in order.

The following steps must be completed one week prior to release:
* Ensure all changes intended to be included in the release are fully merged
* Identify a specific commit as the release candidate
* Raise an issue "Release SPIRE X.Y.Z", and include both the release candidate commit hash and the proposed changelog updates

**If this is a major release**, the following steps must be completed before releasing:
* Review and exercise all examples in spiffe.io and spire-examples repo against the release candidate hash
* Raise a PR for every example that updates included text and configuration to reflect current state and best practice
  * Do not merge this PR yet. It will be updated later to use the real version pin rather than the commit hash
  * If anything unusual is encountered during this process, a comment MUST be left on the release issue describing what was observed

The following steps must be completed to perform a release:
* Cut two annotated tags against the release candidate named `vX.X.X` and `proto/spire/vX.X.X`, where `X.X.X` is the semantic version number of SPIRE
  * The first line of the annotation should be `X.X.X` followed by the changelog. Refer to previous annotated tags as an example
  * The `proto/spire/vX.X.X` tag is needed for proper versioning of the github.com/spiffe/spire/proto/spire go module and can be omitted if/when that go module is no longer in the SPIRE repository.
* Push the tags to SPIRE, and watch the build to completion
  * If the build fails, or anything unusual is encountered, abort the release
    * Ensure that the GitHub release, container images, and release artifacts are deleted/rolled back if necessary
* Visit the releases page on GitHub, copy the release notes, click edit and paste them back in. This works around a GitHub rendering bug that you will notice before completing this task
* Open and merge a PR to bump the SPIRE version to the next projected version and apply the CHANGELOG updates
  * For example, after releasing 0.10.0, update the version to 0.10.1, since it is more likely to be released before 0.11.0.
  * Ideally, this is the first commit merged following the release

**IF this is a major release**, the following steps must be completed no later than one week after the release:
* PRs to update spiffe.io and spire-examples repo to the latest major version must be merged
  * Ensure that the PRs have been updated to use the version tag instead of the commit sha
* Broadcast news of release to the community via available means: SPIFFE Slack, Twitter, etc.

## Community Interaction and Presence
Maintainers represent the front line of SPIFFE and SPIRE community engagement. They are the ones interacting with end users on issues, and with contributors on their PRs.

SPIRE maintainers must make themselves available to the community. It is critical that maintainers engage in this capacity - for understanding user needs and pains, for ensuring success in project adoption and deployment, and to close feedback loops on recently-introduced changes or features... to name a few.

PR and Issue management/response is a critical responsibility for all SPIRE maintainers. In addition, maintainers should, whenever possible:
* Be generally available on the SPIFFE Slack, and engage in questions/conversations raised in the #help and #spire channels
* Attend SPIFFE/SPIRE community events (physically or virtually)
* Present SPIFFE/SPIRE at meetups and industry conferences

### Communication Values
SPIRE maintainers always engage in a respectful and constructive manner, and always follow the [SPIFFE Code of Conduct][6].

It is very important for maintainers to understand that contributions are generally acts of generosity, whether it be creating an issue or sending a pull request. It takes time to do these things. In the vast majority of cases, the motivating factor for taking the time to do this is either to improve the quality of the project for others, or to enable the project to (more easily?) solve a problem that it could not previously. Both of these factors are positive.

Considering the above, optimism and friendliness should be liberally applied to all PR/Issue responses. End users and contributors likely mean their best, and are likely trying their best. It is important to work with them - understand their problem or goal, and constructively work towards a mutually beneficial solution.

This is a very important aspect of SPIRE maintainership. Adoption and contribution decisions are often made on the basis of the attitude (and timeliness) of maintainer responses. This applies not just to GitHub PRs and Issues, but also to the Slack channel and community events. Discouraging or disparaging speech in any arena, like that described in the [code of conduct][6], is unacceptable whether it be intentional or unintentional.


[1]: https://github.com/spiffe/spiffe/blob/master/GOVERNANCE.md
[2]: https://github.com/spiffe/spiffe/blob/master/GOVERNANCE.md#maintainers
[3]: https://github.com/spiffe/spiffe/blob/master/GOVERNANCE.md#change-review-process
[4]: https://github.com/spiffe/spire/blob/master/CONTRIBUTING.md
[5]: https://github.com/spiffe/spire/blob/master/doc/upgrading.md
[6]: https://github.com/spiffe/spiffe/blob/master/CODE-OF-CONDUCT.md
