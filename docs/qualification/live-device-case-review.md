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

## First live observations at e3ef37e (partial; unit not qualified)

The following are retained observations from September 6, 2026, not a
completed performance comparison or a release claim. The whole controller
batches failed; successful sub-workloads are identified separately.

Linux release run `4c3e6499-1b82-40b4-b177-18cdcfee587b` passed at exact
`e3ef37ecff396afaf118484c8189fc505153dc43`. Its native executable SHA-256 is
`24b34be4e0c01a76b20718fa02bb37a5cf169e182bfbd47a101ecd14cc7ac19a`.
The local Windows executable above has unchanged production Rust relative to
this harness-only commit; it was not rebuilt at e3ef37e.

| Executed observation | Result | Interpretation |
| --- | --- | --- |
| Windows desktop to separate Linux/WSL laptop, Silent/Open-policy FullMesh | Waited explicit connect returned active in 2,514.43 ms | One connection, not a distribution; both public pair observations included TURN |
| Same connection, 16 sequential 1,024-byte echo bodies | 16/16 verified at sender and responder, zero loss/duplicate/mismatch/unknown counters; RTT min 42.924, nearest-rank median 43.369, max 45.054 ms | Local monotonic application echo including IPC, not one-way wire time |
| Same workload, sequential verified body rate | 23,420.9 bytes/s | Stop-and-wait application goodput, not saturated bandwidth |
| Closed Windows author stream, first 16 role changes | 196.373 ms total, 81.48 acknowledgements/s | Includes persistent IPC and fsynced measurement records |
| Closed Windows author stream, next 100 role changes | 1,122.078 ms total, 89.12 acknowledgements/s; request median 7.115, p95 8.828, max 11.055 ms | One sequential stream, not independent trial percentiles or isolated signing/fsync cost |
| Canonical export after both streams plus receiver enrollment | 117 unique admitted facts, zero unresolved; all 116 generated IDs present | Local storage confirmation; not receipt by the other device |

First-pair runs are local `40dd0e23-667a-462f-b123-1e592cb77922` and Linux
`0ff03af5-9243-4912-9d93-4f4ae75668d6`. Their retained JSONL hashes are
`4D1E32605A91B87D32909EF1DD189FEF18F6D49A4D300F7BC500070ACD83CC97`
and `7758557532BD375407988D36986AD1D29B386C7D55F9C1EEE97CEA1142FC8659`.
Local copies and a compact observation record are under
`target/qualification-evidence/live-device-inputs/`.

The subsequent 100-by-8,192-byte workload stopped at its first send: the daemon
returned `ok:false`, no send was acknowledged and the receiver saw no request.
The harness discarded the exact refusal text and conservatively recorded
`send_outcome_unknown`; it did not retry. Source inspection proves the current
8,192-unit opaque residual grant cannot fund an 8,192-byte body plus its encoded
command and ownership overhead, even before other use. It does not prove which
refusal occurred first. This cell remains failed/unqualified, not zero network
throughput or a retroactive expected-refusal PASS. The grant is not increased.
Further positive warm comparisons use separately labeled admitted 1 KiB bodies.
The optional larger-body performance cell requires a separately reviewed
compatible complete budget; it must not silently change size or grant.

The payload observer also expected a string recovery tier, whereas public
`peers_list` returns a tagged object such as `{kind:"steady"}`. Its route
observer therefore reported unavailable. Separately retained raw peer snapshots
show both endpoints authenticated, active and bilaterally approved, with a relay
candidate in each selected-pair observation. This remains observational ICE
classification, not nomination proof or an application Hub/opaque-relay test.

Closed runs are local `3bb5c819-0c40-4d3a-b66a-b4df6d875eaf` and Linux
`034fb3f7-2c4a-4de3-8446-5f9434676fcc`. After bootstrap and five explicitly
transferred enrollment pages, both canonical identities matched at 17 admitted
facts and zero unresolved. This was assisted enrollment, not automatic sync.
Closed auto-dial began before that transfer finished; a later explicit connect
overlapped the transition and the connection did not remain usable. The explicit
10-second wait failed. It is not a measurement of intrinsic Closed overhead.
After the additional 100 local facts, the receiver still had 17; automatic
replication and the planned Closed echo were not qualified.

Local Closed JSONL SHA-256:
`9CFA42C56E463166CAD5153B34BFB0381DFE3F2437CA321F34920987ACA4D24E`.
Retained Linux Closed JSONL SHA-256:
`5801E1FA4116FDB112B008539C4018DEB0173BCDB0EE13377F7E05FF38F66899`.
The Linux control run lost its remote transport response around 304 seconds;
the separately retrieved controller log records failed cleanup after SIGINT.
The harness spent its entire shutdown allowance waiting for graceful exit and
left essentially no observation window after SIGKILL. A later exact-PID check
confirmed the owned daemon was gone, not a joined graceful-shutdown success.
Windows owned-child stops were forced. No restart durability claim follows.

Next execution constraints: use a short Unix socket path under a new private
directory; keep remote controller cases within 240 seconds; enroll the Closed
receiver with a minimal baseline before generating measured facts; observe
existing auto-dial state rather than issuing an overlapping explicit connect.
Two scripts-only corrections cover typed peer telemetry/sanitized refusal
evidence and a reserved forced-exit observation interval within the existing
10-second shutdown budget. No Rust or authority change is implied. Hosted CI,
three-device hubs/opaque relay, a non-TURN native baseline, full Open/Closed
comparison, 1,000-fact scale and final independent field audit remain unqualified.

## Native direct observations and scale-controller gate (September 6–7)

These later observations extend the preceding partial report; they do not turn
its failed batches into passes. The operator requested a capacity-gated
500-identity emulation across the three physical computers and a separate
direct/STUN/TURN/application-hub/Closed-opaque-relay matrix. That unit is still
unfinished. No connected 500-node result is claimed.

### Native direct observations

The matched production executable is SHA-256
`51592459BDF32E9E9FD943BC42B24A3E9A8A9174D6254E994C78D03E364C1BDE`.
Its feature-free Windows fingerprint excludes `transport-lab`; the remembered
lab-only forced-TURN environment setting cannot affect that executable. Making
TURN servers available is not a relay-only policy.

| One-connection exploratory workload | Waited connect to active | Verified 1 KiB echoes | Median application RTT | p95 | Maximum |
| --- | ---: | ---: | ---: | ---: | ---: |
| Same-LAN native Windows, STUN/TURN disabled | 342.46 ms | 20/20 | 1.272 ms | 2.106 ms | 3.341 ms |
| Same-LAN native Windows, STUN/TURN available | 129.77 ms | 20/20 | 1.001 ms | 2.210 ms | 47.708 ms |
| Native Windows desktop to home | 1,401.30 ms | 100/100 | 25.026 ms | 28.113 ms | 228.249 ms |

Same-LAN evidence is local run `ee85dfab-5d62-47b9-acc4-79990a07c2cd`
and native laptop run `4b0ea484-986d-4fae-923e-7aad65fb2b90`. Both payload
sub-workloads completed, but their overall collectors expired before the
manager's stop command was consumed and remain censored/failure. The second
network used warm processes. Both sides observed host/host in the available-ICE
case. The operator reported allowing a laptop firewall rule; its timing was not
recorded, so the earlier WSL failure does not isolate WSL/NAT as its cause. The
agent made no firewall or network-mode changes.

Home evidence is local `75188943-001f-4e78-b293-c96caf2b9c2c` and home
`a9262ed4-da8a-40a3-8f7b-836ee15a6bf2`, both exit 0 with complete collectors.
The retained JSONL hashes are respectively
`E63AC14C0EE56EA75E5E839D0B4C1C81CE65FCF374C1B18E3F4E2AFC03F6BDDA` and
`43D03D15C6E825923A9CACB329C84BE8A974012B0086B2156096CA099A18E977`.
Both endpoints observed host/peer-reflexive, consistent with direct
NAT-traversed connectivity, not a selected relay candidate. Public snapshots
are observational and cannot attest the nominated socket or per-payload path.
All RTTs use a sender-local monotonic clock and include IPC/application work.
The outliers remain included. Repeated echoes on one connection are not
independent connection trials, and these values establish no tight-tail SLO.
Windows owned-child termination was forced; no graceful durability follows.

### Capacity-gated emulation, not 500 physical devices

The scale runner owns multiple independent native daemon sessions from one
host controller, rather than one polling Node process per identity. The initial
executable stages are 10, 50, 100, 250 and 500, advanced only after native
capacity and correctness gates. Prepared identities are validated through
`identity_show.data.pubkey`; `status.data.device_id` is a display observation,
not the canonical topology key. All identity homes, pipes, configuration
hashes, per-role limits and host placement remain explicit inputs.

The planner uses supplied identities and the existing rendezvous selector.
For Hubs R1 with 3/3/6/9/12 hubs, the expected steady edge counts are
10/50/109/277/554; HubTree backup0 has 9/49/99/249/499. Actual adjacency must
still be measured. A 500-node full mesh would have 124,750 pairs and is not the
default scale case. Colocated logical edges are labeled separately from
inter-host edges. Neither topology preference nor public snapshots exclude
every transient shortcut.

Each host admits the complete componentwise sum of all 11 provider dimensions
against an explicit host ledger. Independently, the Windows sampler observes
private committed bytes, current/peak working set, actual CPU intervals, host
RAM/commit/disk headroom and registered artifact/log bytes. The original
per-daemon grant is not silently enlarged. The sampled guard is cooperative,
not an OS reservation or proof against transient OOM between samples. Missing
or stale evidence prevents further launch/work; unknown writes are not retried.

The earlier idle calibration, run `8fc1e848-2fc4-43bf-932c-424fac67c8cc`,
sampled ten empty-network native daemons and ten separate Node controllers on
the home machine: 11 observations over 13.3955 seconds. Last mean private
memory was about 3.43 MiB per daemon versus 52.03 MiB per old controller.
Seven controller lifetimes were censored and three completed; all 20 owned
processes were subsequently absent. This motivated sharing a host controller,
but idle values neither predict loaded hub cost nor authorize a 500-node
placement. The retained native sampler file hash is
`03201C5E60992E913D58C8FA4FB0465A04BDD69C6898411421AB99485921E818`.

### Frozen harness verification, not field qualification

The implementation owners are Diffie (peer/host lifecycle), Karp (topology
planner), and Noether (Windows resource collector); none audits their own
implementation. Payne independently closed the frozen planner/collector
dependency gate. Integrated peer/host independent verification found two
capture-boundary blockers, reproduced below. Turing's final whole-unit audit
remains separate.

Three integration defects were reproduced and retained: guard notification did
not cancel an active command, display identity was used in place of canonical
`pubkey`, and the real RPC client did not interrupt a pending reply on work
abort. Runs `5a351caf-900e-42c1-8fd9-2cd1ed6df175` and
`7df3bce9-1e80-45e5-a3fe-3adb1a13f383` preserve the failed guard controls.
The correction carries per-call work cancellation through actual IPC, preserves
a separate bounded cleanup path, joins active command capture before cleanup,
and gathers every started batch outcome with unknown-outcome precedence.

Frozen SHA-256 identities for the 54-control and native lifecycle gates below:

| File | SHA-256 |
| --- | --- |
| `scripts/live-device-peer.mjs` | `81070D9C690BEC8CBF6B407B8F444CD2C9B0AD6FDE2AF7F51ABB358A1F21567C` |
| `scripts/run-live-device-scale-host.mjs` | `3EF7C6E7AFF5F5F9B6F61344AF1615E6A2B646D4CC93A1619B8AA10C054987AA` |
| `scripts/live-device-topology.mjs` | `CC0E99BC34BBC254DFC38B41BEDB68F86526734C5A4290B52D52F40B98BA61C3` |
| `scripts/live-device-resources.ps1` | `9211374C94BB60719AED6702525A46A1F1E01C02968809B1A745A61EDC03F729` |

Run `88fd356c-1bc8-4be5-9f5e-b756e49a1929` passed all 54 combined Node
controls, no failures/cancellations/skips (11,758 stdout bytes, zero stderr).
This includes private IPC and mock controls, not 54 real mesh cases. The earlier
PowerShell run `4ff00ae1-b90c-478a-809a-74b3f66e8d4f` passed 18 injected
resource controls; `c1d9e28d-1385-4d31-b5c1-2ff41a2d5213` exercised native
host/disk/collector counters without owned-child sampling.

Run `9526205f-fc07-481c-b4e1-78edf261fbcd` passed the formerly failing
actual PeerSession/RpcClient check: one held request on private mock IPC,
abort-to-terminal observation 4.6943 ms before a reply was released, no retry,
`outcome_unknown` preserved, and owned native daemon exit observed. This is a
cancellation observation, not mesh latency or an acceptance threshold.

Run `bc64703e-82f6-4062-97f5-88396c138791` passed an actual empty-network
native daemon plus Windows sampler lifecycle: exact controller and daemon
creation-tick pinning, public status and canonical identity, six samples,
zero evidence failures, followed by required daemon exit. Its sampler terminal
reports `observedRequiredExited:true` and honestly `observedAllExited:false`
because the host controller was still alive at its final sample. The run then
exited 0; all three owned processes were checked absent. It does not test a
connected topology, database footprint, or the complete scale-host CLI plan.

All three latest runs used base `a9fdbc5c7b60ddfa37fc2f74a11cdc81a3ff8b34`
and frozen eight-file source manifest
`845315a84223ab756f0d988ae3d5a437380f8eef4aae34087f0755ce0b614d2c`.
Their stdout/stderr were retained to EOF without truncation. Preliminary
harness publication is for clean-checkout field execution only. Connected
10-node configuration/guard integration, loaded capacity placement, larger
stages, matched forced-TURN controls, application hubs/opaque relays, complete
Open/Closed comparison and the final independent field audit remain required.

Payne's subsequent integrated review blocks preliminary publication at this
snapshot despite the positive gates above. In `PeerSession.execute`, an
evidence-capture failure could replace an already-known unknown RPC outcome
with an ordinary failure. The initial `command_started` capture also preceded
installation of the active execution owner, allowing concurrent `close()` to
finish while that capture was still pending. These are harness capture/lifetime
issues, not a newly observed native daemon or network failure.

Manager run `01e9a969-bd81-4ce4-b3c5-eb58dc8695b2` reproduced both boundaries
through actual PeerSession execution with injected RPC/capture callbacks:
returned-unknown and thrown-unknown each lost their unknown classification on
capture failure; holding initial capture allowed close to report complete
before capture release, followed by a late injected RPC invocation. All three
empty-network owned native daemons exited. The run correctly failed its
assertions (721 stdout bytes, 561 stderr bytes, both complete). This is one
paired correction in the peer lifecycle implementation and tests; the host,
planner and collector remain frozen. Publication and multi-node launch remain
paused until correction, runtime verification and independent closure.

The paired capture correction is now runtime-verified at peer SHA-256
`D9B7E7A4CCBA73DF74E3C23022B9CA6137EDF939B11B8BF13D1BF1BFE88A5737`.
It installs the execution owner before initial capture, rechecks cancellation
before dispatch, and preserves known unknown outcomes before fallible result
capture. The host, planner and resource collector hashes above are unchanged.
Peer tests are now
`B868C8FDA916AD5FB4DAEC135A2CB88C9973FAEF36B70BA9C766A1EDAC9D2EB6`.

Run `a5f1c54f-7865-492d-b499-1fc0d1d45d29` passed all 56 combined Node
controls, zero failed/cancelled/skipped, with 12,208 stdout bytes and zero
stderr, complete to EOF. Its nine-file manifest is
`122be53e1cb13336a02a18552fb5e5a15e8395b4c803dfbbb981d67788a59903`
at base `a9fdbc5c7b60ddfa37fc2f74a11cdc81a3ff8b34`.
Two preceding 55/56 runs remain retained: `384ee581-ad13-4df1-b65e-e68c62befab4`
had a new test expecting a censored command status instead of the existing
failed-command/censored-controller distinction; `818eede6-36fc-490c-a5cd-234a01f13850`
then expected an explicit kind on a generic Error. Only test assertions were
corrected. The final control checks the existing controller classifier and
retained terminal status, waits for both resolved and rejected held capture,
and still requires zero late RPC dispatch and joined writer closure.

Actual PeerSession capture probe `176b1404-42e4-435e-b188-f5f9f7d7aa07`
passed all three cases on the same corrected peer implementation: returned
and thrown unknown outcomes survive failed result capture, and held initial
capture prevents close from completing or dispatching late work. Its 791
stdout bytes and zero stderr were complete. All three owned empty-network
native daemons exited and were independently checked absent. RPC and capture
callbacks were injected: this is lifecycle evidence, not a field network test.
Payne independently closed both capture findings at these exact peer/test
hashes after reading the final 56-control and three-case probe logs to EOF.
The preliminary harness-publication gate passes; this is not the final field
audit. The actual connected 10-node pilot, capacity-gated larger stages and
full route matrix remain unqualified, and the operator's release HOLD remains.

### First native connected-10 attempt (2026-09-07 UTC)

The first actual multi-host driver attempt used published harness head
`4cdc19ec1932f61ba1b68a9d5fa9cb7f7fe8231f`, ten distinct prepared native
Windows identities (desktop 2, home 5, laptop 3), and the same feature-free
production executable `51592459...c1bde` and unchanged per-peer grant
`6a214df7...3780a`. All ten passed native configuration parsing, started,
exposed their exact planned canonical public keys, and were observed by the
native resource collector with pinned process-creation identities. The
laptop's operator-corrected execution policy allowed its native scripts to
run; the agent changed no execution policy or firewall rule.

This attempt FAILED and is not a connected-10 performance qualification:

| Host | Durable run | Retained host result |
| --- | --- | --- |
| Desktop | `f70cf685-c3b7-4cae-8fac-0bc5e93b4e37` | Censored at 211.031 s; exit 1 |
| Home | `4355c213-7409-4846-bd5e-fa0f87d8fb5a` | Censored at 210.758 s; remote runner reported target HTTP 400 |
| Laptop | `50a3c967-b517-4ff3-9d4b-b9a9ad3b22b4` | Failed at 133.947 s; remote runner reported target HTTP 400 |

Only the initial `peers_list` phase was issued. The manager did not publish
the payload phase or explicit completion before the finite work window
expired. The desktop/home therefore stopped at the intended work deadline.
Their collectors each retained a successful required-owner-exit terminal
with zero evidence failures; this does not convert the incomplete trial to
success. No payload command was attempted and no RTT was measured here.

The laptop stopped earlier: its last retained samples were complete
`Continue` observations, followed by a host terminal carrying only
`error: {name: "Error"}` and no collector terminal. Existing host error
serialization discarded the discriminating message/code/stage. The original
cause cannot be recovered from those records; a filesystem/manifest failure
is a hypothesis, not an established cause. No retained sample shows a
memory, disk, or other resource-limit breach. Bounded error capture and
autonomous command sequencing are required before another attempt; neither
the resource limits nor the failed historical result may be relaxed.

The ten initial snapshots, taken at different times during startup, contain
all nine intended tree edges in their union: seven appear active,
authenticated and mutually approved in both endpoints' snapshots; the two
later home-to-desktop leaf edges appear in the leaf's snapshot only. All
observed active edges match the plan. LAN pairs show host/host and
cross-town pairs show host/peer-reflexive; none of these snapshots reports a
relay candidate. This is not simultaneous complete adjacency, nomination
attestation, proof of a particular forwarded payload route, or a TURN test.

Observed maximum sums of private committed bytes, including the host
controller and collector, were 209,620,992 (desktop), 212,762,624 (home), and
202,924,032 (laptop). Corresponding maximum summed working sets were
258,035,712, 313,384,960, and 267,902,976 bytes. These sampled startup/idle
observations contain no measured payload load and are not a projection of
500-node capacity. Working-set sums may double-count shared pages.

All ten daemon PIDs and all three host-controller PIDs were subsequently
checked absent; the laptop collector PID was absent too. Windows owned-child
termination remains forced, with no graceful-shutdown durability claim.
The retained host JSONL byte counts and SHA-256 digests are:

- Desktop: 1,512,548 bytes,
  `E096BEF8BB986248283255FCC2FC03837C71E4A4106E8993197EC4CF209FBD28`.
- Home: 2,533,769 bytes,
  `796C471B611AB47DB98872242165E7CAE174FD2F073A0F7BD4FF31415238C340`.
- Laptop: 1,070,827 bytes,
  `BA20E56510531C955773061E157FECB24B232893026566CAD070D1621BB34542`.

Artifacts remain under each host's `pilot10-4cdc19e/connected2` directory.
The manager's bounded joined summary is
`target/qualification-evidence/live-device-inputs/pilot10-4cdc19e/connected2/retained-terminal-summary.json`.
Larger stages, payload throughput/latency, Closed automatic convergence, the
full route matrix, independent final field audit, and release remain unqualified.

### Bounded pilot-harness correction gate (in progress)

The first diagnostic patch failed composed validation: run
`6a2bf124-1e21-49ed-86a2-2fc6a0bcac40` retained 57/59 passing controls.
Its allowlisted OS error was serialized under the generic sensitive field
`code`, so the shared sanitizer correctly redacted it. The correction uses
`os_code` without weakening the shared sensitive-key rule.

Independent review also found that a held diagnostic sink could delay
owned teardown, and a first violation during teardown could miss the final
capture join. Manager reproduction
`c5c79cb0-86d3-4ad5-9eb2-5d75fa4382e9` confirmed both paths using the actual
host controller with mocked peers and collector: zero native daemon starts.
After the host correction (`1553C2FA...C6883A`), the same probe passed in
`f87df078-a0dd-4cc9-97d5-920f9b90c087` (931 stdout bytes, zero stderr,
complete retained logs). Both mock peers closed before a held sink was
released; a delayed teardown capture rejection was joined and preserved as
`outcome_unknown`, including its allowlisted `EPIPE` discriminator.
The combined run `de010ef3-7f89-49e0-8c1d-3ae027b43099` still failed 2 of
63 controls because of a reversed error-field fixture and an unowned
pre-rejected test promise; these failures are retained, not counted as a
successful combined gate.

The autonomous input wrapper initially passed 14 mocked controls in
`54191e3a-3c34-43a6-9acb-06fc81e9aded`. Additional composition diagnostics
then exposed two blockers: a `performance.now()` deadline passed to a
native `process.hrtime`-based sampler was immediately censored
(`7f1d5edc-fb79-4430-a81c-24319565085f`, with a passing same-clock positive
control), and a late joined host `outcome_unknown` was hidden by an earlier
external cancellation (`fec9cd0c-9758-4e03-bf3d-9a84653578c3`). Both
diagnostics launched zero daemons. Earlier diagnostic setup failures
`6dca00d9-93de-4bc1-b5d8-668d8e602d3c` and
`e83e28ea-b382-4bda-bbca-406e21e4f0bc` did not establish those defects and
are not substituted for the corrected reproductions.

No second live pilot has run at this gate. The planned follow-up preserves
the ten identities, network configurations, grants, safety limits and
240-second host envelope; it is not a fresh-identity or fresh-ledger trial.
The fixed autonomous local schedule remains census at 30/45/60 seconds
(four-second capture allowance), qualification by 64 seconds, receiver
ready by 65, sender at 80, final census at 120 and completion by 150.
Those scheduling offsets are not cross-host latency measurements.

The corrected combined host controls subsequently passed 63/63 in
`7b8d174d-f10c-481e-be54-fdd8e03d3768` (13,631 stdout bytes, zero stderr,
complete logs), with host hash `1553C2FA...C6883A` and test hash
`E7E488B4...D4B4CB`. Independent review then identified a distinct remaining
deadline composition: an already-settled ambiguous capture result was
discarded if cleanup exhausted the deadline before the final join. The
expanded actual-host/mock-owner probe
`53fddb53-7012-4af8-8e66-bb1d8b579fe0` reproduced that loss while retaining
the two earlier positive cases. This remains a host publication blocker;
the 63 passing controls do not establish that missing boundary.

Wrapper hash `47048D86...F54017` and test hash `34AD179E...55C0240` passed
19/19 controls in `93c45314-24ff-43b7-b82c-a05a07fe50c7` (4,462 stdout
bytes, zero stderr, complete logs), including the wrapper's actual default
clock composed with the real sampler gate without starting a process. The
manager's late-unknown reproduction also passed after correction in
`9c911500-1e82-4ec7-9e4d-61e2a07d5702` (171 stdout bytes, zero stderr).
An independent wrapper source/control review found no blocking interface or
schedule contradiction. Final hash-bound case inputs, corrected host
deadline handling, deployed-byte custody, live execution and final field
audit remain separate gates.

The owned settled-result latch (`CBF73371...F56F8CB`) passed the expanded
64-control suite in `593c660e-1127-4019-b08e-4339bb4a102f` (13,850 stdout
bytes, zero stderr, complete logs). The three-case capture-owner probe also
passed in `f1d2ac7f-df77-498c-b669-aa871b929b85` (1,470 stdout bytes,
zero stderr), including preservation of the already-settled `EPIPE`
unknown outcome after cleanup reached the original deadline. The unresolved
expired-capture case still remains censored; no deadline was extended.
These are source/helper validation results, not another live mesh result.

Independent verification of the frozen `CBF73371...F56F8CB` host and
`AC8749F9...71118A` controls closed the reproduced diagnostic/capture
blockers after reading both final runs in full. This permits preliminary
harness publication only; it does not replace the separate case-input,
deployment, actual network workload or final independent field-audit gates.

### Windows sampler-heartbeat correction: preliminary qualification

The current operator scope is a measured chart through 100 nodes; larger
tests are deferred. This section records a harness correction, not a
successful 50-node or 100-node measurement. PR #7 remains open, draft,
unmerged and on HOLD. The existing release/CI block is not waived.

#### Retained live failure and bounded diagnosis

The first connected50 attempt used the previously qualified 50 identities
and prepared configurations. All three trials terminated unsuccessfully:

| Host | Durable run | Retained outcome |
| --- | --- | --- |
| Desktop | `c916bc4f-3515-4f81-ae70-5b8e9a6c9a6a` | Exit 1; sampler-manifest heartbeat `EPERM` / `rename` / -4048 after 619 ms, before any peer terminal. |
| Home | `bc05686b-29a1-44bf-8a64-a8f0a15b15c6` | Remote control plane reported HTTP 400; separately retained native evidence records the same heartbeat failure after approximately 49 seconds and 21 peers. |
| Laptop | `90843b4b-6537-4ce3-8c93-21cdfbab25dc` | Remote control plane reported HTTP 400; separately retained native evidence is censored after approximately 102 seconds and 15 peers. |

An HTTP 400 control-plane response is not proof that no native work ran.
These are failed/censored trials, not measured memory exhaustion, capacity
limits or connected50 qualification. Their artifacts and used journals remain
retained; no fresh trial may silently reuse them.

Finite native file-replacement diagnostics reproduced Windows `EPERM` even
with a reader opened with Read/Write/Delete sharing. Removing the manifest
from diagnostic self-accounting did not eliminate the failure. These results
do not identify the particular production handle or exclude an external
scanner. The corrected reader-exposure probe
`10dc89c1-8f9f-450d-81be-2e52a2547985` retained explicit stop acknowledgements,
owned exits and the first-replacement failure for both sharing controls.

#### Correction and unchanged boundaries

The host now owns a serialized atomic manifest publisher. Only Windows
`EPERM` from `rename`, following a prior successful publication, is eligible
for bounded replacement retry. The publisher reuses the same uniquely
created, written, synced and closed temporary file, bytes and revision.
Before retrying it checks the intended temporary's identity/content and
the prior target's identity/content/size/timestamps. It rechecks cancellation
and time after awaited custody reads. Retry stops at the earlier of the
existing manifest-freshness cutoff and the full host deadline; pacing uses
the existing heartbeat interval. No grant, sampler policy, workload deadline
or teardown reserve is increased.

Initial publication, non-Windows failures and other error classes remain
one-shot. Uncertain target or temporary custody latches `outcome_unknown`
and fences already-queued, later and teardown publications. Cleanup is
restricted to the exact owned temporary; changed or uncertain files are not
silently removed. This is not a general filesystem or network/RPC retry.

Normal sampler close marks only its own cancellation objects in a private
WeakSet. A queued heartbeat refused by that owned close does not invent a
violation. External cancellation and real prior/in-flight errors or unknown
outcomes remain failures. Close still joins publication, collector and
capture ownership. This does not guarantee recovery from sustained Windows
contention or make pre-rename checks a continuous exclusive filesystem lease.

#### Candidate controls and native evidence

The candidate is based on published head
`a0f42fc380feaf7eec35f1081e83142b5f1c1436`. Its two changed source files are:

- Host SHA256: `C8FD37F848A2896E43C4D37B70CC159302FCF6BE8B7FFAD6ED50BC23D6F066DF`.
- Maintained tests SHA256: `D502BCB7DBF09398D5309D44C80F2AE9A2DCA9F8514536D9A84BD5663487F36D`.

Combined run `ba34eb5b-edc7-44c3-aca4-165187bc593a` passed 96/96 tests,
exit 0, with 20878 stdout bytes, zero stderr, both streams read through EOF,
and no failures, skips, cancellations or truncation. This includes 90
maintained controls and six unchanged manager regression controls. The
complete two-file candidate source manifest is
`caa18b9f0173ad31d0eadc0c87efbf571c317938832e35e4d8d119100bd6ff48`.

Native run `dc4d2e74-5716-4ce2-bfff-3eb6a1c3eadf` passed all six cells
and the complete final probe terminal, exit 0, 3818/0 bytes through EOF:

| Native boundary | Observation |
| --- | --- |
| Uncontended publisher | 61 successful replacements, revisions 1 through 61. |
| Brief held shared-delete reader | Three real EPERM failures, then the exact same temporary became revision 2. |
| Sustained reader | Ten failures; last rename attempt at 4901.0345 ms, before the 5010.768 ms freshness cutoff; old revision retained. |
| Abort during contention | Two failures, then bounded stop with old revision retained. |
| Full deadline during contention | Four failures; last rename attempt at 1836.55 ms, before the 2200 ms cutoff; old revision retained. |
| Actual PowerShell sampler | 30 publications, 12 samples and a complete successful terminal; no first violation. |

All four readers acknowledged explicit stop and exited without force; no
temporary files remained in any cell. Cleanup/join finished 15.30 ms and
12.64 ms after the sustained/full cutoffs respectively, without a rename
attempt at or after those cutoffs.

The actual sampler used one finite Node helper registered as a daemon-role
owner solely to exercise creation pinning and required-exit accounting.
No mesh daemon or network started. Two bootstrap owner-unconfirmed samples
remain incomplete; the other ten are complete/Continue. The terminal records
zero evidence failures and requiredExited=true, while its controller was
still alive. The helper and collector exited; a manager read-only census
subsequently found controller 55768, helper 29196 and collector 60520 absent.
These small harness observations are not scale or durability evidence.

Ignored native probe SHA256:
`57B0EFD084F615FA270106B877BD0E747109747A16CDC82FC94800CF1B9100CB`.
Retained artifacts are under
`target/qualification-evidence/live-device-inputs/atomic-native-a962iO`:

- `summary.json`: `47FBC892D2B179EFC433DB09EE09D05ECA600D77EE8B2E5A0B21039786119663`.
- `actual_sampler/evidence.json`: `FE9C0A181B593A0CE06D741998192D526B3E6DFACFB1AC80F2FE36B175AA575D`.
- `actual_sampler/result.jsonl`, 35754 bytes / 13 rows: `2625AC438659BECC1F849583082D4AA94D9BCD66D5BFECC8E1EDA999F2EF4432`.

Ignored artifacts are bound by these explicit hashes, not by tracked Git
cleanliness, and are not hosted attachments. The earlier incomplete native
run `f69aa94e`, failing native run `375a6d33`, four-boundary reproduction
`ad0f855e`, normal-close reproduction `30e7023a` and fixture failures remain
in the local `pilot50-a0f42fc/c1/heartbeat-retry-boundary-findings.md` ledger.
None is relabeled as passing.

Diffie implemented the two-file correction. Payne independently read the
final source, maintained and manager controls, both complete durable logs,
six raw native cell artifacts and all sampler owner/phase/decision rows.
His bounded SOURCE/CONTROL/native verdict is PASS; he made no implementation
changes. This supports preliminary correction publication only. Exact
pushed-head execution and Turing's independent audit are separate subsequent
gates. Connected50 recovery, the chart through100, field paths, performance
and graceful durability remain unqualified at this checkpoint.
