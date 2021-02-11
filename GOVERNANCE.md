# Athenz Governance

As a CNCF member project, we abide by the [CNCF Code of Conduct](https://github.com/cncf/foundation/blob/master/code-of-conduct.md).

For specific guidance on practical contribution steps for any Athenz sub-project please see our [CONTRIBUTING.md](CONTRIBUTING.md) guide.

## Maintainership

There are different types of maintainers, with different responsibilities, but all maintainers have 3 things in common:

1) They share responsibility in the project's success.
2) They have made a long-term, recurring time investment to improve the project.
3) They spend that time doing whatever needs to be done, not necessarily what is the most interesting or fun.

## Reviewers

A reviewer is a core role within the project. They share in reviewing issues and pull requests, and their **thumbs up** counts towards 
the required **thumbs up** count to merge a code change into the project.

Reviewers may or may not have write access. Being a reviewer is key to becoming a maintainer.

## Adding maintainers

Maintainers are first and foremost contributors that have shown they are committed to the long term success of a project. 
Contributors wanting to become maintainers are expected to be deeply involved in contributing code, pull request review, and triage of issues 
in the project for more than three months.

Just contributing does not make you a maintainer, it is about building trust with the current maintainers of the project and being a person 
that they can depend on and trust to make decisions in the best interest of the project.

If you are interested in becoming a maintainer and satisfy the requirements above, please open up a pull request. The existing maintainers 
are given five business days to discuss the candidate, raise objections and cast their vote. Votes take place via pull request comment. 
Candidates must be approved by at least 66% of the current maintainers by adding their vote. Only maintainers of the repository that the 
candidate is proposed for are allowed to vote.

If a candidate is approved, a maintainer will contact the candidate to invite the candidate to open a pull request that adds the contributor 
to the `MAINTAINERS` file. The candidate becomes a maintainer once the pull request is merged.

## Maintainer responsibilities

- Monitor email aliases.
- Monitor Slack (delayed response is perfectly acceptable).
- Triage GitHub issues and perform pull request reviews for other maintainers and the community.
- Triage build issues - file issues for known flaky builds or bugs, and either fix or find someone to fix any main build breakages.
- During GitHub issue triage, apply all applicable labels to each new issue. Labels are extremely useful for future issue follow up. Which labels to apply is somewhat subjective so just use your best judgment. A few of the most important labels that are not self explanatory are:
    - **beginner**: Mark any issue that can reasonably be accomplished by a new contributor with this label.
    - **help wanted**: Unless it is immediately obvious that someone is going to work on an issue (and if so assign it), mark it help wanted.
    - **question**: If it's unclear if an issue is immediately actionable, mark it with the question label. Questions are easy to search for and close out at a later time. Questions can be promoted to other issue types once it's clear they are actionable (at which point the question label should be removed).
- Make sure that ongoing PRs are moving forward at the right pace or closing them.

## Subprojects

Athenz subprojects are divided into two flavors: **core** and **non-core**. Definition of a **core** subproject is any repository within the 
AthenZ GitHub organization, which is **core** to the delivery of the Athenz project's releases.

Non-core projects have a strong affiliation with Athenz, but operate similarly to the traditional `contrib/` directory in many open source 
projects. For example the auth0 authority or Server metrics interface implementation for Prometheus.

In most cases the maintainer list will be unique, and the project can have unique release, support, and maintainer processes. 
Non-core projects may be written in other languages and therefore require different skills, developer tools, and CI systems than the 
core projects. For these reasons, non-core subprojects have a few unique properties that are described in the section 
"_Adding non-core subprojects_" below.

Both core and non-core subprojects must adhere to the CNCF [charter](https://www.cncf.io/about/charter/) and mission.

Core maintainers have maintainer privileges across all core and non-core projects to help contribute to project health, maintenance, 
and release processes within the GitHub organization. For ease of list management, the `MAINTAINERS` file of a sub-project will only 
list the sub-project maintainers—the core maintainers of Athenz will not be appended to each subproject.

## Adding core subprojects

New core subprojects can request to be added to the AthenZ GitHub organization by submitting a project proposal via public forum 
(a `AthenZ/athenz` GitHub issue is the easiest way to provide this proposal). The existing maintainers are given five business days to 
discuss the new project, raise objections and cast their vote. Projects must be approved by at least 66% of the current maintainers.

If a project is approved, a maintainer will add the project to the AthenZ GitHub organization, and make an announcement on a public forum.

## Adding non-core subprojects

Non-core subprojects will also submit a project proposal via GitHub issue, and should state that the project is expected to be non-core.

The proposal should include a proposed list of maintainers who will manage the non-core project and provide general information on support, 
releases, stability, and any additional detail useful for the Athenz maintainers to understand the scope and nature of the project.

The existing maintainers are given five business days to discuss the new project, raise objections and cast their vote. Projects must be 
approved by at least 66% of the current maintainers.

If a project is approved, a core maintainer will add the project to the AthenZ GitHub organization and provide write access for that 
repository to the proposed maintainer list, and make an announcement on a public forum.

Unlike core maintainers, non-core project maintainers are responsible for maintenance tasks in their subproject only.

## Stepping down policy

If you're a maintainer but feel you must remove yourself from the list, inform other maintainers that you intend to step down, 
and if possible, help find someone to pick up your work. At the very least, ensure your work can be continued where you left off.

After you've informed other maintainers, create a pull request to remove yourself from the `MAINTAINERS` file.

The Athenz organization will never forcefully remove a current maintainer, unless a maintainer fails to meet the principles of Athenz community,
or adhere to the [CNCF Code of Conduct](https://github.com/cncf/foundation/blob/master/code-of-conduct.md).

## How are decisions made?

Decisions are built on consensus between maintainers. Proposals and ideas can either be submitted for agreement via a GitHub issue, PR or 
GitHub discussions.

All proposals, ideas, and decisions by maintainers should either be part of a GitHub issue, PR or GitHub discussions.

## I'm a maintainer. Should I make pull requests too?

Yes. Nobody should ever push to master directly. All changes should be made through a pull request. The only exception is when we cut a release
using maven release action, which commits the changes to the version numbers directly to the master branch.

## Conflict Resolution

If you have a technical dispute that you feel has reached an impasse with a subset of the community, any contributor may open an issue, 
specifically calling for a resolution vote of the current core maintainers to resolve the dispute. The same voting quorums required (2/3) 
for adding maintainers will apply to conflict resolution.

## Credits

Sections of this document have been borrowed from [Containerd](https://github.com/containerd/project/blob/master/GOVERNANCE.md) and
[CoreDNS](https://github.com/coredns/coredns/blob/master/GOVERNANCE.md) projects.