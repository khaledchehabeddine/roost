# Triage Labels

The skills speak in canonical category and state roles. This file maps those roles to the labels used in this repo's issue tracker.

## Category roles

| Canonical role | Tracker label | Meaning                    |
| -------------- | ------------- | -------------------------- |
| `bug`          | `bug`         | Defect or broken behavior  |
| `enhancement`  | `feature`     | New feature or improvement |

## State roles

| Canonical role      | Tracker label       | Meaning                                  |
| ------------------- | ------------------- | ---------------------------------------- |
| `needs-triage`      | `needs-triage`      | Maintainer needs to evaluate this issue  |
| `needs-info`        | `needs-info`        | Waiting on reporter for more information |
| `ready-for-agent`   | `ready-for-agent`   | Fully specified, ready for an AFK agent  |
| `ready-for-human`   | `ready-for-human`   | Requires human implementation            |
| `wontfix`           | `wontfix`           | Will not be actioned                     |

Every triaged issue carries exactly one category label and one state label. When a skill names a canonical role, use its mapped tracker label.
