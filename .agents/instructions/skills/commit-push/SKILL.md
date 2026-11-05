# Commit Push

Follow [CONTRIBUTING.md](../../../../CONTRIBUTING.md) for Git conventions.

1. Identify this task's changes, including untracked files.
2. Verify them with the verify skill, unless this task already verified them and nothing changed since.
3. Start a subagent that runs your `Review Skills` on this branch's changes against `origin/main`, including uncommitted and untracked files. Give it only the task. Run it once per pull request, and again after a fix that changes behavior. Let the user pick which findings to fix, then run the verify skill again if you fixed any.
4. Plan the branch name, each commit's files and message, and any amend or force push.
5. Draft the pull request title and description from every commit on the branch. Follow the [pull request template](../../../../.github/PULL_REQUEST_TEMPLATE.md), with your `Pull Request Footer` as its last line. Fill the Verification section from `.scratch/verify.md`. Carry forward any earlier Unchecked and Limitations items that still apply.
6. Show the plan and the pull request title and description in chat, then wait for the user to confirm.
7. Commit and push as planned. Create or update the draft pull request with the label its branch starts with, assign it to the user, and return its link.
