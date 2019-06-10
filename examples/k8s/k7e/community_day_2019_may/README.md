# Demo from SPIRE Community Day, May 2019

This example will allow you to recreate the demo from SPIRE Community Day in
May, 2019. To run this example you'll need:

+ A working minikube.
+ `kubectl` version 1.14 or later.
+ The [examples/k8s/k7e](/examples/k8s/k7e) directory tree from the SPIRE github
  repository.

## Running the demo

The steps below assume everything is being run from the `community_day_2019_may`
directory.

### Status

You can run a script similar to the following in one terminal to see what pods
are running:

```
$ watch 'set -x; kubectl get pods -n spire; kubectl get pods'
```

### Deploy SPIRE

To deploy SPIRE, apply the `base_minikube_sat` configuration from the parent
directory:

```
$ kubectl apply -k ../base_minikube_sat
```

Within 30 seconds or so, you should now have pods in "Running" status for both
`spire-server` and `spire-agent`:

```
$ kubectl get pods -n spire
NAME                READY   STATUS    RESTARTS   AGE
spire-agent-6f9bk   1/1     Running   0          24s
spire-server-0      1/1     Running   0          24s
```

### Deploy Workload Container

The demo deploys a `spire-agent` container for the purposes of shelling into to
validate that the workload container was attested to SPIRE.

Deploy the workload container:

```
$ kubectl apply -f client-deployment.yaml
```

Within a few seconds you should have a `client` pod in "Running" status:

```
$ kubectl get pods
NAME                     READY   STATUS    RESTARTS   AGE
client-7fd8d6ffc-zxd9l   1/1     Running   0          11s
```

### Shell Into Workload Container

Next, we'll get shell into the running workload container so we can interact
with the SPIRE workload API:

```
$ kubectl exec -it $(kubectl get pods --selector=app=client --output=jsonpath="{..metadata.name}") /bin/sh
/opt/spire # 
```

At this point you should have shell into the container.

### Workload Is Not Attested

We'll now see that the workload is not attested to SPIRE because we haven't
yet created any registration entries.

```
/opt/spire # bin/spire-agent api fetch -socketPath /run/spire/sockets/agent.sock 
rpc error: code = PermissionDenied desc = no identity issued
```

`no identity issued` means that our workload is not attested (and in fact, you
may realize at this point we haven't even provided any registration entries
for `spire-agent` - so even our SPIRE agent cannot attest to the `spire-server`
yet).

### Add Registration Entries

OK, let's fix the lack of agent and workload attestation by providing some
registration entries. We'll create two registration entries:

+ `spiffe://example.org/cluster` - This entry will be a `node` registration
  used to attest `spire-agent` as a cluster node.
+ `spiffe://example.org/client` - This entry will be for our client workload.

**Note:** Run the following from the system where you've been running all the
`kubectl` commands, **not** from within the client workload container!

First, let's create the `node` registration entry:

```
$ kubectl exec -n spire spire-server-0 -- /opt/spire/bin/spire-server entry create -node -spiffeID spiffe://example.org/cluster -selector k8s_sat:cluster:demo-cluster

Entry ID      : 1685a30f-fb14-4242-a86a-568038407ed7
SPIFFE ID     : spiffe://example.org/cluster
Parent ID     : spiffe://example.org/spire/server
TTL           : 3600
Selector      : k8s_sat:cluster:demo-cluster
```

Second, we'll create a registration entry for our client workload:
```
kubectl exec -n spire spire-server-0 -- /opt/spire/bin/spire-server entry create -parentID spiffe://example.org/cluster -spiffeID spiffe://example.org/client -selector k8s:sa:default

Entry ID      : 6bfd9727-60be-45a8-941c-65ffc94676af
SPIFFE ID     : spiffe://example.org/client
Parent ID     : spiffe://example.org/cluster
TTL           : 3600
Selector      : k8s:sa:default
```

If everything works, you'll get output similar to the above (but with different
entry IDs).

### Workload is Now Attested

Now, if we pop back into our client workload container, we'll see that the
workload has now been attested (this might take 30-60 seconds or so after
creating the registration entries):

```
/opt/spire # bin/spire-agent api fetch -socketPath /run/spire/sockets/agent.sock 
Received 1 bundle after 10.08623ms

SPIFFE ID:		spiffe://example.org/client
SVID Valid After:	2019-05-14 17:07:23 +0000 UTC
SVID Valid Until:	2019-05-14 18:07:33 +0000 UTC
CA #1 Valid After:	2019-05-14 16:42:41 +0000 UTC
CA #1 Valid Until:	2019-05-15 16:42:51 +0000 UTC
```

Alternatively, you can use `api watch` instead of `api fetch` and see when the
registration entry gets pushed down through the agent to the workload.

### Poke Around

Feel free to poke around at the various configurations and see what happens
if you perform operations such as deleting the registration entries from the
`spire-server`.

### Clean Up

When done, run the following commands to delete all the Kubernetes objects we
created above:

```
$ kubectl delete deploy client
$ kubectl delete namespace spire
```

