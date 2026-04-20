# Developer tooling for running Cassandra datastore tests

The scripts and compose file here can be used to run a single Cassandra datastore test or the whole suite via Visual
Studio Code's launch/debug tooling.

Add the following to `.vscode/tasks.json`:
```json
{
    "tasks": [
        {
            "label": "start cassandra",
            "type": "shell",
            "command": "bash",
            "args": [
                "${workspaceFolder}/test/integration/cassandra-suites/datastore-cassandra-focus/extras/debug-setup.sh"
            ]
        },
        {
            "label": "stop cassandra",
            "type": "shell",
            "command": "bash",
            "args": [
                "${workspaceFolder}/test/integration/cassandra-suites/datastore-cassandra-focus/extras/debug-teardown.sh"
            ]
        }
    ]
}
```

Add the following to as a launch configuration in `.vscode/launch.json`:
```json
{
    "name": "Debug Cassandra integration tests",
    "type": "go",
    "request": "launch",
    "mode": "test",
    "program": "${workspaceFolder}/pkg/server/datastore",
    "buildFlags": [
        "-ldflags",
        "-X github.com/spiffe/spire/pkg/server/datastore_test.TestDialect=cassandra -X github.com/spiffe/spire/pkg/server/datastore_test.TestConnString=[\"localhost:9053\"];spire_test"
    ],
    "cwd": "${workspaceFolder}/pkg/server/datastore",
    "args": [
        "-test.parallel",
        "1",
        "-test.v",
        // "-testify.m",
        // "^(TestPruneAttestedNodeEvents)$"
    ],
    "preLaunchTask":"start cassandra",
    "postDebugTask": "stop cassandra",
}
```

If you'd like to run a single test, uncomment the `"-testify.m"` arg and the `"^(TestPruneAttestedNodeEvents)$"` arg.
Replace `TestPruneAttestedNodeEvents` with whatever test function you would like to run.

Happy debugging!