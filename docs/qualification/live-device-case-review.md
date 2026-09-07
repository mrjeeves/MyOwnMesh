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
