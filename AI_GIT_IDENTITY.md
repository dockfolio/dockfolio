# Git identity notice

Read this before committing from any machine or any AI session.

Every repository under github.com/konradreyhe commits under a single author
identity so the GitHub contribution graph stays consolidated under one account.
Set this once on each machine you commit from:

    git config --global user.name  "konradreyhe"
    git config --global user.email "140392634+konradreyhe@users.noreply.github.com"

Do not commit under any other email (not ccprompt@, not a personal address).
Commits under a different email do not count toward the contribution graph and
re-fragment authorship, which then needs another full history rewrite to repair.

## History was rewritten

On 2026-06-17 the author history of every repo was rewritten to unify identity.
Old commit hashes no longer exist on the remotes. If you have an old local clone,
do not force-push it. Re-clone fresh, or run:

    git fetch origin && git reset --hard origin/<default-branch>
