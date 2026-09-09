//! The operations behind the control protocol's request match.
//!
//! The exhaustive `match` over [`Request`](super::Request) lives with the
//! connection loop in `control.rs`, and stays there: totality is a property of
//! one match over one enum, and per-domain sub-enums would need a `_ =>`
//! somewhere to glue them back together. What lives here is the work an arm
//! delegates to: the per-domain operation modules, and the shared helpers each
//! of them funds an answer or a refusal through.
//!
//! No function here takes a `Request`. Each takes the fields its arm
//! destructured, so nothing below the total match can be handed a variant it
//! does not handle, and the connection loop's match over `Request` is total,
//! so the compiler enforces that.

use anyhow::{Context, Result};

pub(super) mod channel;
pub(super) mod governance;
pub(super) mod identity;
pub(super) mod network;
pub(super) mod opaque;
pub(super) mod realtime;
pub(super) mod rpc;
pub(super) mod services;
pub(super) mod updater;

use crate::control::framing::{AdmittedLineOut, FrameAdmission, PreparedLineCapacity};
use crate::control::reply::{ControlOut, PreparedReply, PreparedText};

/// One admitted answer: what to say, and the funding that lets it be said.
///
/// Every operation module hands this back rather than a bare reply, because
/// the reply alone would leave its line to be funded afterwards — the ordering
/// the funding work exists to remove. Handing back the capacity the reply was
/// admitted under makes "this was measured before the operation committed" a
/// property of the return type instead of a convention each arm re-enacts.
///
/// The pairing is also why the connection loop stays the only encoder and the
/// only writer. An operation that could write would need the socket, the
/// cancellation token and the loop's `continue`/`break` control flow; one that
/// answers only says what it wants said, and cannot get the sequence wrong.
pub(in crate::control) type Answer = (PreparedReply, PreparedLineCapacity);

/// Fund the line for a reply that is already decided.
///
/// This measures and funds a decided answer through the same serialization path
/// that `write_line` uses. It does not prove that any effect described by the
/// answer preceded the final fallible line admission.
pub(in crate::control) fn funded(
    reply: PreparedReply,
    admission: &FrameAdmission,
) -> Result<Answer> {
    let output = AdmittedLineOut::prepare(&ControlOut::Prepared(&reply), admission)
        .context("control response line was not admitted")?;
    Ok((reply, output))
}

/// Fund a refusal whose text is a fixed string.
pub(in crate::control) fn refused(
    message: &'static str,
    admission: &FrameAdmission,
) -> Result<Answer> {
    funded(PreparedReply::StaticError(message), admission)
}

/// Fund a refusal whose text this daemon formats.
///
/// The text is owned under the response owner this acquires, and is measured
/// only by the writer's pass over the sealed reply.
pub(in crate::control) fn refused_text(
    message: String,
    admission: &FrameAdmission,
) -> Result<Answer> {
    let text = PreparedText::acquiring(message, admission)
        .context("control refusal text was not admitted")?;
    funded(PreparedReply::Error(text), admission)
}

/// The refusal every network-scoped operation shares: no such joined network.
pub(in crate::control) fn unknown_network(
    network: &str,
    admission: &FrameAdmission,
) -> Result<Answer> {
    refused_text(format!("unknown network: {network}"), admission)
}
