# SPIRE Maintainership Guidelines and Processes

This document captures the values, guidelines, and processes that the SPIRE project and its maintainers adhere to. All SPIRE maintainers, in their independent and individual capacity, agree to uphold and abide by the text contained herein.

This process can be changed, either permanently or as a one-time exception, through an 80% supermajority maintainer vote.

For a list of active SPIRE maintainers, please see the [CODEOWNERS](CODEOWNERS) file.

## General Governance

The SPIRE project abides by the same [governance procedures][1] as the SPIFFE project, and ultimately reports to the SPIFFE TSC the same way that the SPIFFE project and associated maintainers do.

TSC members do not track day-to-day activity in the SPIFFE/SPIRE projects, and this should be considered when deciding to raise issues to them. While the SPIFFE TSC has the ultimate say, in practice they are only engaged upon serious maintainer disagreement. To say that this would be unprecedented is an understatement.

### Maintainer Responsibility

SPIRE maintainers adhere to the [requirements and responsibilities][2] set forth in the SPIFFE governance document. They further pledge the following:

* To act in the best interest of the project at all times.
* To ensure that project development and direction is a function of community needs.
* To never take any action while hesitant that it is the right action to take.
* To fulfill the responsibilities outlined in this document and its dependents.

### Number of Maintainers

The SPIRE project keeps a total of five maintainer seats. This number was chosen because 1) it results in a healthy distribution of responsibility/load given the current volume of project activity, and 2) an odd number is highly desirable for dispute resolution.

We strive to keep the number of maintainers as low as is reasonably possible, given the fact that maintainers carry powerful privileges.

This section of the document can and should be updated as the above considerations fluctuate. Changes to this section of the document fall under the same requirements as other sections. When changing this section, maintainers must re-review and agree with the document in its entirety, as other guidelines (e.g. voting requirements) will likely change as a result.

### Changes in Maintainership

SPIRE maintainers are appointed according to the [process described in the governance document][2]. Maintainers may voluntarily step down at any time. Unseating a maintainer against their will requires a unanimous vote with the exception of the unseated.

Unseating a maintainer is an extraordinary circumstance. A process to do so is necessary, but its use is not intended. Careful consideration should be made when voting in a new maintainer, particularly in validating that they pledge to uphold the terms of this document. To ensure that these decisions are not taken lightly, and to maintain long term project stability and foresight, no more than one maintainer can be involuntarily unseated in any given nine month period.

The CNCF MUST be notified of any changes in maintainership via the CNCF Service Desk.

#### Onboarding a New Maintainer

New SPIRE maintainers participate in an onboarding period during which they fulfill all code review and issue management responsibilities that are required for their role. The length of this onboarding period is variable, and is considered complete once both the existing maintainers and the candidate maintainer are comfortable with the candidate's competency in the responsibilities of maintainership. This process MUST be completed prior to the candidate being named an official SPIRE maintainer.

The onboarding period is intended to ensure that the to-be-appointed maintainer is able/willing to take on the time requirements, familiar with SPIRE core logic and concepts, understands the overall system architecture and interactions that comprise it, and is able to work well with both the existing maintainers and the community.

## Change Review and Disagreements

The SPIRE project abides by the same [change review process][3] as the SPIFFE project, unless otherwise specified.

The exact definition/difference between "major" and "minor" changes is left to maintainer's discretion. Changes to particularly sensitive areas like the agent's cache manager, or the server's CA, are always good candidates for additional review. If in doubt, always ask for another review.

If there is a disagreement amongst maintainers over a contribution or proposal, a vote may be called in which a simple majority wins. If any maintainer feels that the result of this vote critically endangers the project or its users, they have the right to raise the matter to the SPIFFE TSC. If this occurs, the contribution or proposal in question MUST be frozen until the SPIFFE TSC has made a decision. Do not take this route lightly (see [General Governance](#general-governance)).

### Security and Usability

SPIRE solves a complicated problem, and is developed and maintained by people with deep expertise. SPIRE maintainers must ensure that new features, log and error messages, documentation and naming choices, are all easily accessible by those who may not be very familiar with SPIFFE or authentication systems in general.

Decisions should favor "secure by default" and "it just works" anywhere possible, and in that order. The number of configurables should be minimized as much as possible, especially in cases where it's believed that many users would need to invoke it, or when their values (and extremes) could significantly affect SPIRE performance, reliability, or security.

A good measure is the "beginner" measure. A beginner should be able to easily and quickly understand the configurable/feature, and its potential uses/impacts. They should also be able to easily and quickly troubleshoot a problem when something important goes wrong - and not to mention, be clearly informed of such a condition!

### Review Guidelines

The SPIFFE [governance document][1], its section on [review process][3], and the SPIRE [contribution guidelines][4], must all be applied for any SPIRE review.

While reviewing, SPIRE maintainers should ask questions similar to the following:

* Do I clearly understand the use case that this change is addressing?
* Does the proposed change break any current user's expectations of behavior (i.e. regression)?
* Is it possible for this change to be misconfigured? If it is, what is the impact?
* Does the proposed change adhere to the SPIRE [compatibility guarantee][5]?
* What are the failure modes? Can SPIRE keep running?
* If something goes wrong, will it be clear to the operator what it was and how to fix it?
* If this change introduces additional configurables, is it possible to replace some or all of them with a programmatic decision?

The above list is advisory, and is meant only to get the mind going.

## Release and Branch Management

See [RELEASING.md](RELEASING.md).

## Community Interaction and Presence

Maintainers represent the front line of SPIFFE and SPIRE community engagement. They are the ones interacting with end users on issues, and with contributors on their PRs.

SPIRE maintainers must make themselves available to the community. It is critical that maintainers engage in this capacity - for understanding user needs and pains, for ensuring success in project adoption and deployment, and to close feedback loops on recently-introduced changes or features... to name a few.

PR and Issue management/response is a critical responsibility for all SPIRE maintainers. In addition, maintainers should, whenever possible:

* Be generally available on the SPIFFE Slack, and engage in questions/conversations raised in the #help and #spire channels.
* Attend SPIFFE/SPIRE community events (physically or virtually).
* Present SPIFFE/SPIRE at meetups and industry conferences.

### Communication Values

SPIRE maintainers always engage in a respectful and constructive manner, and always follow the [SPIFFE Code of Conduct][6].

It is very important for maintainers to understand that contributions are generally acts of generosity, whether it be creating an issue or sending a pull request. It takes time to do these things. In the vast majority of cases, the motivating factor for taking the time to do this is either to improve the quality of the project for others, or to enable the project to (more easily?) solve a problem that it could not previously. Both of these factors are positive.

Considering the above, optimism and friendliness should be liberally applied to all PR/Issue responses. End users and contributors likely mean their best, and are likely trying their best. It is important to work with them - understand their problem or goal, and constructively work towards a mutually beneficial solution.

This is a very important aspect of SPIRE maintainership. Adoption and contribution decisions are often made on the basis of the attitude (and timeliness) of maintainer responses. This applies not just to GitHub PRs and Issues, but also to the Slack channel and community events. Discouraging or disparaging speech in any arena, like that described in the [code of conduct][6], is unacceptable whether it be intentional or unintentional.

## Product Management and Roadmap Curation

In addition to the maintainer seats, the SPIRE project designates one product manager seat. While maintainers strive to ensure that project development and direction is a function of community needs, and interact with end users and contributors on a daily basis, the product manager works to clarify user needs by gathering additional information and context. This includes, but is not limited to, conducting user research and field testing to better inform maintainers, and communicating project development information to the community.

Maintainers are expected to have heavy participation in the community, but it may be impractical to dedicate themselves to gathering and analyzing community feedback and end-user pain points. Based on data collection, the role of the product manager is intended to aid maintainers to validate the desirability, feasibility, and viability of efforts to help drive project direction and priorities in long term planning.

The role has three primary areas of focus: roadmap management and curation (to ensure the project direction is representative of the community's needs), program management (to help the project deliver on its strategy and meet its intended outcomes), and project management (to align day-to-day activities to meet the SPIRE project requirements).

The product manager must:

* Work with the maintainers to continually ensure a high-quality release of the projects including owning project management, issue triage and identifying all features in the current release cycle.
* Regularly attend maintainer sync calls.
* Participate actively in Request for Comments and feature proposal processes.
* Track feature development and ongoing community undertakings.
* Coordinate changes that result from new work across the larger project and provide clarity on the acceptance, prioritization and timeline for all workstreams and efforts.
* Communicate major decisions involving release planning to the developer and end user communities through the project media, communication channels, and community events.
* Manage the relationship between SPIFFE/SPIRE and the CNCF.
* Support the marketing and promotion of the SPIFFE and SPIRE project through the CNCF with the objective to foster a more secure cloud native ecosystem.
* Coordinate and facilitate discussions on policy review and changes with the TSC.

The product manager makes the same pledge as maintainers do to act in the best interest at all times and its seat follows the same change guidelines as maintainer seats as described in the governance document. Unseating a product manager against their will requires a unanimous vote by the maintainers.

## Community Facilitation and Outreach

The project designates a community chair to work with the product manager seat to focus on growing awareness of the project and increasing community engagement. In this role, the community chair is responsible for community outreach and outbound communication.

The responsibilities of the community chair are as follows:

* Maintain, share with the community and execute a plan for proposed marketing and community outreach activities every release cycle.
* Coordinate and facilitate community events (online and in-person).
* Maintain and manage the spiffe.io website, ensuring that it stays available and up-to-date.
* Coordinate social media communications.
* Ensure that all community events and meetings are recorded, and make the recordings available and discoverable on YouTube.
* Ensure that all community meeting notes, discussions, and designs are easily discoverable on Google Docs.
* Encourage use of project official channels for all technical and non-technical discussions.
* Periodically communicate marketing and community activity to maintainers and the TSC
* Protect the privacy and confidentiality of non-public community information, including personal contact information such as email addresses and phone numbers.
* Onboard contributors and welcome them into the community.

[1]: https://github.com/spiffe/spiffe/blob/main/GOVERNANCE.md
[2]: https://github.com/spiffe/spiffe/blob/main/GOVERNANCE.md#maintainers
[3]: https://github.com/spiffe/spiffe/blob/main/GOVERNANCE.md#change-review-process
[4]: https://github.com/spiffe/spire/blob/main/CONTRIBUTING.md
[5]: https://github.com/spiffe/spire/blob/main/doc/upgrading.md
[6]: https://github.com/spiffe/spiffe/blob/main/CODE-OF-CONDUCT.md
