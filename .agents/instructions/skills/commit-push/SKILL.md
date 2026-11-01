# Commit Push

Follow [CONTRIBUTING.md](../../../../CONTRIBUTING.md) for Git conventions.

1. Identify this task's changes, including untracked files.
2. Verify them with the verify skill, unless this task already verified them and nothing changed since.
3. Start a subagent that runs your `Review Skills` on this branch's changes against `origin/main`, including uncommitted and untracked files. Give it only the task. Let the user pick which findings to fix, then run the verify skill again if you fixed any.
4. Plan the branch name, each commit's files and message, and any amend or force push.
5. Draft the PR title and description from every commit on the branch. Follow the [PR template](../../../../.github/PULL_REQUEST_TEMPLATE.md), with your `PR Footer` as its last line. Fill the Verification section from `.scratch/verify.md` and any earlier Unchecked items that still apply.
6. Show the plan and the PR title and description in chat, then wait for the user to confirm.
7. Commit and push as planned, create or update the draft PR, and return its link.
