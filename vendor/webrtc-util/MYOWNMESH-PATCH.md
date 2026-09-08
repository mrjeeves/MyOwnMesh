# Opt-in real UDP socket configuration

Source: crates.io webrtc-util 0.11.0, checksum
`64bfb10dbe6d762f80169ae07cf252bafa1f764b9594d140008a0231c0cdce58`.
Upstream source, tests, manifests, and both licenses are retained.

The only source change adds `Net::with_udp_socket_config`. It configures
real bound/connected UDP sockets before they are exposed to their caller.
Default callers and virtual networks retain upstream behavior. MyOwnMesh
uses this through SettingEngine's existing network injection hook; it does
not change ICE candidates, socket ownership, or multiplexing architecture.

Stream PC's Winsock AFD trace on 2026-09-08 recorded 366 datagrams discarded
from the active media source in 20 seconds: "Insufficient local buffer space".
Adapter captures separately showed original RTP arriving in order before
application loss/recovery. A fresh Windows UDP socket measured 65,536 bytes
of receive capacity, below AMS's existing 96 KiB burst allowance.

MyOwnMesh opts in to bounded 1 MiB receive capacity. Socket reads still drain
immediately; no playout delay, fill threshold, bitrate/FPS cap, or application
media queue change is introduced. Actual capacity is logged at socket setup,
with a warning if the OS clamps it. Existing larger capacities are not reduced.

Focused core tests exercise bound and connected sockets. The Windows burst
regression compares the 64 KiB baseline with the configured socket using the
existing media burst envelope before scheduling the receiver.
