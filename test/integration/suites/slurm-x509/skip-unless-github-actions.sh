# Sourced at the top of every step script and the teardown.
#
# This suite installs Slurm and munge on the host, starts host systemd services,
# and manipulates the host cgroup tree (see README.md). That is only appropriate
# on the ephemeral GitHub Actions runners the SPIRE integration job uses.
#
# Running it on a developer workstation would modify the host, so on any machine
# that is not a GitHub Actions runner this prints a notice once and exits the
# step with success. Because every step (and teardown) exits 0, the framework
# reports the whole suite as succeeded, making it safe to run locally.
if [ "${GITHUB_ACTIONS:-}" != "true" ]; then
    if [ ! -f "${RUNDIR}/.gha-skip-notified" ]; then
        log-warn "the \"slurm-x509\" suite only runs on GitHub Actions runners (it installs Slurm/munge and changes host cgroups); skipping on this machine, reported as success."
        : > "${RUNDIR}/.gha-skip-notified" 2>/dev/null || true
    fi
    exit 0
fi
