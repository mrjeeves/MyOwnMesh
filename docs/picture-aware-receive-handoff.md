# Picture-aware receive repair and IPC handoff

This patch addresses two independently reproduced receive-path failures.
It does not change bitrate, resolution, FPS, encoder recovery mode, or the
150 ms RTP repair grace. The binary media protocol is unchanged.

## Repair before handoff

The RTP assembler used to accept late packets only when their timestamp
already had a pending entry. If every packet of a picture arrived after a
newer picture, it rejected all of the older picture's repairs. The newer
picture then remained blocked behind the sequence hole those packets could
have repaired.

The assembler now inserts a previously unseen older timestamp into a known,
unretired sequence hole. Its sequence must fall after the emitted anchor and
between the observed neighboring pictures. It does not rewind the newest
timestamp or revive retired data. The inserted entry inherits the hole's
existing deadline, so late arrival cannot buy another repair interval.

The regression `entirely_reordered_picture_is_repaired_before_newer_picture`
failed on the old implementation and passes with this change, including RTP
timestamp wraparound. Companion tests cover deadline inheritance and invalid
sequence boundaries. Existing fragment, marker, sequence-wrap, encrypted
repair, and genuine-loss bounds remain covered.

## Preserve repaired fragments through IPC

One encoded picture can consist of many paced, marker-delimited RTP samples.
The daemon-to-client queue formerly counted eight **samples**, so a single
repaired picture could overflow it while the socket reader was briefly busy.
A scheduler yield cannot make a blocked socket writable.

Admission now counts distinct `(peer, lane, RTP timestamp)` pictures, retaining
the eight-slot limit. Audio and unrecognized bodies consume individual slots.
This intentionally allows more than eight fragments of one picture, while
bounding total queued payload to the existing 64 MiB wire-body limit and
metadata to 4096 samples. These are maximum queue bounds, not a target buffer
level; each body is offered to the writer immediately. The writer can have
one additional in-flight body, as before. No complete-picture wait or playout
delay is introduced. Real overflow still orders a discontinuity before
subsequent video, leaving codec recovery policy with the application.

`repaired_picture_crosses_media_pipe_with_a_temporarily_busy_reader` sends 32
24 KiB fragments through the actual binary pipe writer, using a 4 KiB duplex
pipe whose reader remains busy during admission. The legacy eight-sample
queue rejects the ninth sample; the new path delivers every body in order.
The bridge regression additionally checks that this release does not invent
a discontinuity, while a genuinely full picture budget still does. Queue
tests cover byte, item, peer/lane and audio bounds, and cleanup on disconnect.

## Validation boundary

These tests establish the two specific defects and their corrections. They
do not identify every possible source of initial RTP loss or scheduling delay,
and do not prove every observed field stall has the same cause. The application
must use a daemon containing both changes before a paired field comparison is
meaningful. No live application settings or processes need to be changed to
run the focused tests.
