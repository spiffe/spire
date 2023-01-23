# SPIRE Server CLI Suite

## Description

This suite validates that we can run both spire agent and spire server natively on Windows OS, asserting that spire components
can run as a [windows service application](https://learn.microsoft.com/en-us/dotnet/framework/windows-services/introduction-to-windows-service-applications#service-applications-vs-other-visual-studio-applications),
and perform [service state transitions](https://learn.microsoft.com/en-us/windows/win32/services/service-status-transitions).

The suite steps are structured as follows:

1. Spire server and agent are installed as Windows services.
2. Spire server and agent services starts, their respective status is asserted as **_RUNNING_**, and the node attestation
is performed with x509pop.
3. Workload registration entries are created.
4. The feature of fetching SVIDs (x509 and JWT) is asserted with the running spire agent service.
5. Spire server and agent services are stopped, their respective status is asserted as **_STOPPED_**, and graceful
shutdown is verified via application logs.
6. Spire server and agent services are started again, but this time with an invalid config; their respective status is
asserted as **_STOPPED_**.
