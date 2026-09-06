# Live-device mesh case review

Status: controller implementation and local startup smoke passed; device-to-device
performance execution pending. No live network performance result yet.
This is the operator-approved next unit after the bounded Graph/Hub review at
`c5f6d221f9cb6a8100ec2165ffae6d7c6eafeb15`. The earlier 175-test result is
correctness evidence, not a device performance baseline. PR #7 stays draft,
unmerged and HOLD; unrelated hosted CI repairs are outside this unit.

## Execution sequence

1. Build the production release daemon without `transport-lab`, bind every
   executable to its source, platform and SHA-256, and validate the controller.
2. Establish one actual two-device connection and deliver a byte-verified echo.
   Classify any failure at launch, discovery, negotiation, approval or payload.
3. Repeat the matched cases below. A failed smoke does not become a long
   permutation/audit exercise: retain the exact failure and fix or report the
   smallest demonstrated execution blocker.
4. Independently verify the retained observations, then have Turing audit the
   exact published head and claims. Publish results and stop for operator review.

The local Windows desktop and the two granted remote devices have different
hostnames. The laptop's selected Linux environment is WSL, not another physical
machine. Their observed private interfaces are on different subnets; no LAN,
mDNS reachability or direct NAT traversal is inferred from management access.
The management connection's timing is never mesh RTT.

## Finite case set

| Case | Shape | Work and comparison |
| --- | --- | --- |
| Native connection baseline | Two hosts, Silent/Open governance, no hub | Fresh network; discovery sighting, explicit dial, approved active session, first verified payload |
| Open direct | Two hosts, FullMesh | Same channel echo workload as Closed |
| Closed direct | Two hosts, FullMesh | Establish authority before timing; same channel echo workload |
| Hubs | Three roles on three hosts | Spoke–hub–spoke, Open and Closed, matched payloads |
| HubTree | Five roles, three available hosts | Explicitly disclose colocated roles and actual inter-host edges; Open and Closed payloads |
| Opaque relay | Three roles on three hosts, Closed only | Open/Accept readiness, bidirectional verified frames, warm echo and close |
| Fact stream | Closed writer/receiver, separate churn target | Smoke 16, then independent 100 and 1,000 alternating role grants; automatic replication and exact final export |
| Catch-up and restart | Closed, 100-fact bounded history | Disconnected-receiver catch-up; same-home orderly Linux restart and one further operation |

First payload smoke: 16 echoes of 1,024 data bytes. Warm descriptive workloads:
100 echoes each at 1,024 and 8,192 data bytes, bounded by the actual returned
relay frame limit and IPC envelope. Sequential echo goodput is not saturated
bandwidth. Connection distributions target 20 independent fresh-network trials
per measured scenario where feasible; cold-process and warm-process samples
remain separate. Smaller completed groups are explicitly exploratory. Neither
20 samples nor a percentile is a statistical confidence guarantee.

Each command has an explicit deadline; the initial discovery/dial/payload
readiness envelope is 60 seconds per stage. These are finite collection bounds,
not product SLOs. Keep timeouts/refusals and denominators, without replacing them
with extra successful attempts. No 10,000-fact escalation or resource-cap growth
is automatic. Only one measured case per host runs at a time, after builds stop.

## Policy and route controls

Use fresh isolated test homes and synthetic facts/payloads; never change the
operator's normal daemon config, identity, services or firewall. Windows roles
use explicit, distinct local named pipes through `daemon.control_socket` and
the controller's JSONL client; the existing CLI's fixed-pipe behavior is not
used for these roles. Refuse a preexisting endpoint. Colocated POSIX roles need
separate homes and socket paths. Record
every exact PID/start identity and stop only processes started by this trial.
Windows forced termination must be labeled forced, not graceful durability.
Disable auto-update in these isolated test configs (`enabled:false`,
`auto_apply:"none"`) so the measured executable cannot change during a case.

All eleven provider grant dimensions and the complete semantic policy are
explicit, retained case inputs. They are finite test budgets, not inferred
production defaults or a performance promise. Refusal under a budget is a
result, not permission to increase it silently. Keep paired cases' policies
equal where the workloads are comparable. Open has no governance fact stream;
it is a payload/control-cost comparison, not zero-cost Closed semantics.

The initial per-daemon test grant is: accounted memory 1 GiB; queued bytes
256 MiB; sockets/handles 4,096; native objects 8,192; workers/tasks 8,192;
callbacks 65,536; storage 4 GiB; storage objects 65,536; relay allocations 1,024;
parsing/CPU work 1,048,576; opaque residuals 8,192. These are logical ceilings,
not preallocated OS usage. The separately retained explicit semantic policy
allows 100,000 admitted facts, 10,000 per author and 64 hot-history facts; this
unit generates at most 1,000 per workload. No omitted dimension or automatic
growth is permitted. Actual runtime acceptance of these inputs is still pending.

Use the project's configured reference Nostr/STUN/TURN service recipe where
cross-subnet discovery requires it; record the exact selected server policy.
Do not enable arbitrary public fallback, invent credentials, force a private
lab connector, or call TURN configured merely because a link actually used it.
Public ICE pair classification is observational: nomination is not guaranteed
by that field. Distinguish ICE TURN from the Closed application opaque relay.

Hub maintenance starts with the existing nonfast 4–8 second Trickle and 4 second
exploration policy, with the same 2 second state-watch period in paired cases.
Those are configuration intervals, not measured delivery times. Parent expiry
must cover the finite payload window; test expiry separately from steady state.
Record intended/observed adjacency and epochs on all roles before/after traffic.
Unexpected direct shortcuts contaminate a routed sample. Public snapshots do
not certify that no transient shortcut existed between observations. Exact
parent acceptance and directory pagination timestamps are not exposed by the
production daemon; do not substitute lab snapshots or claim them from payloads.

## Measurements and result rules

- Record discovery, approved transport and first byte-verified echo separately.
  Echo RTT uses one endpoint-local monotonic clock and includes application/IPC
  overhead. Never subtract clocks on different hosts.
- Retain raw sample times, intended/delivered unique bytes, losses, duplicates,
  mismatches and failures. Recompute nearest-rank min/p50/p95/max from valid raw
  samples, with attempted/completed/failed/censored counts alongside them.
- Fact RPC acknowledgement is not proof of insertion or replication. Retain
  returned unique IDs, compare both complete canonical exports after quiescence,
  and require equal context/counts/state/projection commitments and unresolved=0.
  Automatic-sync cases never import measured pages into the receiver. Assisted
  page transfer, if needed, is a separate labeled case.
- Separate serial fact RPC time/rate from observed replication catch-up.
  Identity polling has cost and supplies an observation upper bound, not exact
  one-way replication latency or internal queue depth. Fsync and checkpoint
  subphase times are unavailable from the public daemon.
- Sample real daemon CPU, current residency, lifetime high-water residency and
  exact main/WAL/SHM/journal file sizes at phase boundaries. Use finite periodic
  samples where useful. Windows private committed bytes and Linux private
  resident bytes are different metrics. Resource claims are not OS memory.
- Treat fresh process/fresh slot, restarted existing database and warm session
  separately. None is an OS-cold-cache claim; no cache flush or system tuning.
- Controller/remote orchestration, compilation, bootstrap and observation cost
  stay visible and outside the defined warm payload interval. All benchmark
  instrumentation and binaries are hashed; unavailable counters remain null.

## Initial execution evidence

Local Windows release build `ab84bce1-79a6-4357-90c1-6d8f92dbf7ac` passed at
the baseline head (optimized release, 7m38s; not a cold-build benchmark).
`myownmesh.exe` SHA-256:
`51592459BDF32E9E9FD943BC42B24A3E9A8A9174D6254E994C78D03E364C1BDE`.

Remote Windows attempt `1fb503fb-97c4-468c-82ec-f898d0ce9be2` ended with
target HTTP 400, no compiler logs and no exit code. Subsequent read-only checks
found no cargo/rustc process and confirmed cargo 1.88.0; a separate durable
runner smoke `d7575259-20c1-42c6-9b60-0e9363dcee9c` passed. This is execution
setup evidence, not a MyOwnMesh compiler or runtime failure.

Linux prerequisite `390e1b55-2666-4f4d-a3b7-603a86ac04e8` successfully sourced
the already-installed Rust environment and confirmed pinned 1.88.0. Build
`35ab70fe-ee00-47dc-af76-161cca952ab2` did not start: the runner's subsequent
unsourced PATH check still rejected cargo/rustc. No installer is needed. Remote
builds must also wait for the controller's clean published checkout, as required
by the runner. These setup attempts contribute no live network measurements.

The first local startup smoke `d32c778e-e835-4d35-8d69-eea39647ef74` failed
before control-endpoint readiness. An embedded startup/shutdown diagnostic
`262cdf9e-f3c9-4a16-889b-35e37982dc87`, linked against the same release libraries,
exposed a retained `control/create_tokio` failure. Read-only inspection found
the default `myownmesh.sock` pipe still present after the test processes exited,
and another MyOwnMesh process that predated the trial. That existing process
and endpoint were left untouched. With the same release-linked diagnostic and
grant, a fresh isolated home using the supported custom local pipe setting
passed startup and joined shutdown in run
`4cdfc421-33de-4495-97ff-558a5e1912ea`. This clears the observed bind failure
without changing Rust source. The controller-driven `serve`/status smoke and
cross-device delivery remain separate, pending checks.

Eight mocked workload controls passed in run
`82d87656-8204-4bc8-a8f9-a8e6bd08df99`. Independent integration inspection then
found that the endpoint controller did not propagate some returned workload
failures into its aggregate status. A scripts-only correction and focused
controller tests passed: all 19 checks in run
`8453499a-0dd5-471a-87ac-3e7672cab6d9`, zero failures or skipped tests.
Mock results do not establish live delivery,
and no failed or incomplete field workload has been accepted as a performance
sample.

Actual production `serve` plus controller status/explicit-stop smoke
`9405ee41-4f58-4d80-87ed-460c225304b6` passed with the isolated Windows pipe.
The daemon replied `ok:true` to status and the controller retained a complete
terminal record and exited zero. The single local status request took 5.97 ms;
this is an IPC smoke observation, not mesh RTT or a latency distribution.
Shutdown was owned-child forced termination on Windows and is not a graceful
durability claim. The existing unrelated daemon remained running.

Payne independently verified the corrected controller's result propagation,
the complete 19-test capture, and the actual isolated startup/status/stop
evidence. That finite preliminary publication check passed. The device case
results and final live-unit audit are still pending; this is not release
readiness or removal of PR HOLD.
