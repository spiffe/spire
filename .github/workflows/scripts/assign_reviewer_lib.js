// Shared ball-in-court helpers for the assign-reviewer workflows
// (assign_reviewer.yaml and assign_reviewer_review_apply.yaml).
//
// The ball is tracked through the PR assignee. The court holder is the
// single flow participant (a pool member or the PR author) currently
// assigned. Activity-driven flips (pushes, conversation comments, the
// author's review replies) only happen when the acting user holds the
// ball, so repeated events are no-ops and those flips never override a
// manual assignee change. The initial assignment on open and the flips on
// pool-member review submissions move the court unconditionally, and
// setCourt only ever touches flow participants, leaving unrelated,
// manually-added assignees in place.
//
// This file is always loaded from a trusted ref (the PR base branch, or
// the default branch on workflow_run and issue_comment), never from PR
// code. See the checkout step in each workflow.

module.exports = async function ({ github, context, core }) {
  const { owner, repo } = context.repo;
  const eq = (a, b) => a.toLowerCase() === b.toLowerCase();

  // The reviewer pool lives in .github/reviewer-pool.json so it has a
  // single, discoverable source of truth. Read it from the default branch
  // (the API default ref) so a PR from a fork cannot substitute its own
  // pool.
  const { data: poolFile } = await github.rest.repos.getContent({
    owner, repo, path: '.github/reviewer-pool.json',
  });
  const pool = JSON.parse(
    Buffer.from(poolFile.content, poolFile.encoding).toString('utf8'),
  ).reviewers;

  const inPool = (login) => pool.some(p => eq(p, login));

  const isBot = (user) =>
    user.type === 'Bot' || user.login.endsWith('[bot]');

  // The flow participant currently holding the ball, or null when no
  // participant is assigned or the state is ambiguous (for example, a
  // manually co-assigned maintainer next to the author). Handlers treat
  // null as "do not touch".
  function courtHolder(pr) {
    const author = pr.user.login;
    const assigned = (pr.assignees || []).map(a => a.login);
    const maintainers = assigned.filter(a => inPool(a) && !eq(a, author));
    const authorAssigned = assigned.some(a => eq(a, author));
    if (authorAssigned && maintainers.length === 0) {
      return author;
    }
    if (!authorAssigned && maintainers.length === 1) {
      return maintainers[0];
    }
    return null;
  }

  // The pool member (other than the author) who most recently submitted a
  // review, or null when nobody from the pool has reviewed yet. Used as
  // the flip-back target when the author acts without re-requesting a
  // review. Callers that already listed the PR's reviews can pass them to
  // skip the refetch.
  async function lastPoolReviewer(pr, reviews = null) {
    reviews ??= await github.paginate(github.rest.pulls.listReviews, {
      owner, repo, pull_number: pr.number, per_page: 100,
    });
    for (let i = reviews.length - 1; i >= 0; i--) {
      const login = reviews[i].user && reviews[i].user.login;
      if (login && inPool(login) && !eq(login, pr.user.login)) {
        return login;
      }
    }
    return null;
  }

  // Make `login` the sole ball-in-court assignee among flow participants
  // (the pool members and the PR author), leaving any unrelated,
  // manually-added assignees untouched.
  async function setCourt(pr, login) {
    const flow = [...pool, pr.user.login];
    const current = (pr.assignees || []).map(a => a.login);
    const toRemove = current.filter(a =>
      flow.some(f => eq(f, a)) && !eq(a, login));
    if (toRemove.length > 0) {
      await github.rest.issues.removeAssignees({
        owner, repo, issue_number: pr.number, assignees: toRemove,
      });
    }
    if (!current.some(a => eq(a, login))) {
      await github.rest.issues.addAssignees({
        owner, repo, issue_number: pr.number, assignees: [login],
      });
    }
    core.info(`Ball in court: ${login}, PR #${pr.number}.`);
  }

  return { pool, eq, inPool, isBot, courtHolder, lastPoolReviewer, setCourt };
};
