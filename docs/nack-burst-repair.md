# Retain repair information across the actual sender burst

The receive NACK history was reduced to 512 sequence bits to bound repair
traffic. Its contract test assumed AMS's previous 200 Mbps burst ceiling.
AMS's current frame-budget pacer permits 256 Mbps with a 96 KiB burst.
A ~627 KiB encoded frame alone can advance an early missing packet beyond
512 positions before the first 20 ms feedback tick. The assembler still waits
up to 150 ms for a repair that the NACK generator has silently forgotten.

`motion_burst_hole_is_nacked_and_repaired_before_assembly_deadline` reproduces
this with the actual interceptor and H.264 assembler, including sequence wrap.
The old configuration fails: no NACK is sent for the early missing fragment,
and the assembler emits a discontinuity. With 1024 history bits, that fragment
is requested and its arrival releases the intact frame and the following one.
The test failed on the former production configuration before the correction.

History retention is now independent of feedback work: the generator remembers
1024 packets but requests at most 512 missing packets per track per tick. A
focused feedback test confirms the remaining holes are still requested once
the earlier repairs arrive. The existing stale-repair alias guard remains
enabled by default. The diagnostic legacy-history switch must be disabled for
the corrected live test; it intentionally restores the known corruption bug.

No media queue, bitrate/FPS target, pacing rate, 150 ms assembly deadline,
20 ms feedback interval, eight-packet reorder tail, or 8192-packet authenticated
replay/responder window changes. This is not a claim that every packet loss
or network scheduling stall has been eliminated. Live validation must check
actual executing binaries and settings, not infer them from branch names.
