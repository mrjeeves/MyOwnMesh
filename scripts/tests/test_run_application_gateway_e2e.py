from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch



SCRIPT = Path(__file__).parents[1] / "run-application-gateway-e2e.py"
SPEC = importlib.util.spec_from_file_location("application_gateway_e2e", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


COMPLETE_GRANT = ",".join(f"{name}=100" for name in runner.GRANT_DIMENSIONS)


class ApplicationGatewaySurfaceControls(unittest.TestCase):
    def test_surface_contract_requires_every_shipped_phase(self) -> None:
        observations = [{"surface": name, "ok": True} for name in runner.REQUIRED_SURFACE]
        assert runner.missing_surface(observations) == ()
        runner.require_surface(observations)

    def test_surface_contract_rejects_realtime_skip(self) -> None:
        observations = [
            {"surface": name, "ok": True}
            for name in runner.REQUIRED_SURFACE
            if name != "realtime_flow_pipe"
        ]
        observations.append({"surface": "realtime_flow_pipe", "ok": True, "skipped": True})
        self.assertIn("realtime_flow_pipe", runner.missing_surface(observations))
        with self.assertRaises(runner.ContractError):
            runner.require_surface(observations)

    def test_run_is_fail_closed_when_manifest_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(runner.ContractError):
                runner.require_manifest(Path(temporary) / "manifest.json", False)


    def test_surface_contract_reports_missing_operations(self) -> None:
        observations = [
            {"surface": "events_subscribe", "ok": True},
            {"surface": "rpc_unary", "ok": True},
        ]
        assert runner.missing_surface(observations) == tuple(
            name
            for name in runner.REQUIRED_SURFACE
            if name not in {"events_subscribe", "rpc_unary"}
        )
        try:
            runner.require_surface(observations)
        except runner.ContractError as error:
            assert "channel_send_to" in str(error)
            assert "realtime_flow_pipe" in str(error)
        else:
            raise AssertionError("partial application surface must fail closed")


    def test_realtime_wire_round_trip_preserves_exact_opaque_bytes(self) -> None:
        label = b"e2e-audio"
        payload = b"\x00\xffopaque\x00payload"
        frame = runner.encode_realtime_send(label, payload)
        length = int.from_bytes(frame[:4], "little")
        assert length == len(frame) - 4
        # The shipped inbound framing has its own header and prefix.  This
        # fixture exercises the decoder without pretending the outbound and
        # inbound timestamp fields have the same meaning.
        inbound = (
            len(label).to_bytes(1, "little")
            + b"\x01"
            + (42).to_bytes(4, "little")
            + len(payload).to_bytes(4, "little")
            + label
            + payload
        )
        assert runner.decode_realtime_recv(inbound) == (label, 42, payload)


    def test_realtime_decoder_rejects_truncated_and_mismatched_frames(self) -> None:
        with self.assertRaises(runner.ContractError):
            runner.decode_realtime_recv(b"\x01\x00")
        label = b"x"
        payload = b"y"
        wrong_length = (
            b"\x01\x00"
            + (1).to_bytes(4, "little")
            + (99).to_bytes(4, "little")
            + label
            + payload
        )
        with self.assertRaises(runner.ContractError):
            runner.decode_realtime_recv(wrong_length)

    def test_grant_parser_requires_exact_finite_u64_dimensions(self) -> None:
        parsed = runner.validate_grant(COMPLETE_GRANT)
        self.assertEqual(set(parsed), set(runner.GRANT_DIMENSIONS))
        self.assertEqual(parsed["worker_or_task"], 100)
        invalid = (
            "",
            "accounted_memory_bytes=1",
            f"{COMPLETE_GRANT},worker_or_task=101",
            f"{COMPLETE_GRANT},unknown=1",
            COMPLETE_GRANT.replace("worker_or_task=100", "worker_or_task=nope"),
            COMPLETE_GRANT.replace("worker_or_task=100", "worker_or_task=-1"),
            COMPLETE_GRANT.replace("worker_or_task=100", f"worker_or_task={runner.U64_MAX + 1}"),
            COMPLETE_GRANT.replace("worker_or_task=100", "worker_or_task=" + "1" + "0" * 5000),
            COMPLETE_GRANT.replace("worker_or_task=100", "worker_or_task=1=2"),
        )
        for raw in invalid:
            with self.assertRaises(runner.ContractError, msg=raw):
                runner.validate_grant(raw)


    def test_source_contains_public_control_operations(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        for operation in (
            '"events_subscribe"',
            '"channel_send_to"',
            '"channel_send_reliable"',
            '"rpc_call"',
            '"rpc_call_stream"',
            '"rpc_respond"',
            '"rpc_stream_chunk"',
            '"rpc_stream_end"',
            '"capabilities_set"',
            '"realtime_flow_open"',
            '"realtime_pipe"',
            '"realtime_flow_close"',
        ):
            assert operation in source
        assert "localbroker" not in source.lower()


    def test_finite_grant_and_policy_validation(self) -> None:
        if os.name != "posix":
            self.skipTest("the production harness intentionally requires AF_UNIX")
        class Args:
            binary = Path(sys.executable)
            timeout = 1.0

        runner.validate_args(Args(), COMPLETE_GRANT, "disabled")
        for grant in ("", "unbounded=1", "infinite"):
            try:
                runner.validate_args(Args(), grant, "disabled")
            except runner.ContractError:
                pass
            else:
                raise AssertionError("non-finite grant must be refused")

    def test_mocked_production_run_exercises_controls_and_terminal_cleanup(self) -> None:
        class FakeProcess:
            next_pid = 41000

            def __init__(self) -> None:
                self.pid = FakeProcess.next_pid
                FakeProcess.next_pid += 1
                self.returncode = 0

            def poll(self) -> int:
                return self.returncode

        class FakeReader:
            def __init__(self, lines: list[bytes]) -> None:
                self.lines = iter(lines)
                self.closed = False

            def readline(self, limit: int = -1) -> bytes:
                del limit
                try:
                    return next(self.lines)
                except StopIteration:
                    return b""

            def close(self) -> None:
                self.closed = True

            def __enter__(self) -> "FakeReader":
                return self

            def __exit__(self, *args: object) -> None:
                del args
                self.close()

        class FakeRpcSocket:
            def __init__(self, state: dict[str, object]) -> None:
                self.state = state
                self.closed = False

            def settimeout(self, timeout: float) -> None:
                del timeout

            def connect(self, path: str) -> None:
                self.state["rpc_path"] = path

            def sendall(self, data: bytes) -> None:
                self.state["rpc_body"] = json.loads(data.decode("utf-8"))

            def makefile(self, mode: str) -> FakeReader:
                assert mode == "rb"
                body = self.state["rpc_body"]
                assert isinstance(body, dict)
                response = {"ok": True, "data": {"response": {"echo": body["payload"]}}}
                return FakeReader([json.dumps(response).encode("utf-8") + b"\n"])

            def close(self) -> None:
                self.closed = True

        class FakePipe:
            def __init__(self) -> None:
                self.closed = False

            def sendall(self, data: bytes) -> None:
                del data

            def shutdown(self, how: int) -> None:
                del how

            def close(self) -> None:
                self.closed = True

        class FakeBinaryReader:
            def __init__(self, data: bytes) -> None:
                self.data = data
                self.closed = False

            def read(self, size: int = -1) -> bytes:
                if size < 0:
                    size = len(self.data)
                chunk, self.data = self.data[:size], self.data[size:]
                return chunk

            def close(self) -> None:
                self.closed = True

        class FakeEventClient:
            def __init__(self, name: str, state: dict[str, object]) -> None:
                self.name = name
                self.state = state
                self.client_id = f"client-{name}"
                self.capability = f"cap-{name}"
                self.closed = False
                self.chunk = 0

            def close(self) -> None:
                self.closed = True

            def until(self, label: str, timeout: float, predicate: object) -> dict[str, object]:
                del timeout
                network = self.state["network"]
                assert isinstance(network, str)
                if label in {"typed channel inbound", "reliable typed channel inbound"}:
                    frame = {
                        "kind": "channel_inbound",
                        "network": network,
                        "channel": runner.CHANNEL,
                        "from": "device-a",
                        "payload": self.state["payload"],
                    }
                elif label == "unary RPC inbound":
                    body = self.state["rpc_body"]
                    assert isinstance(body, dict)
                    frame = {
                        "kind": "rpc_inbound",
                        "network": network,
                        "from": "device-a",
                        "method": runner.UNARY_METHOD,
                        "payload": body["payload"],
                        "request_id": "req-unary",
                        "operation_id": 1,
                    }
                elif label == "streaming RPC inbound":
                    frame = {
                        "kind": "rpc_inbound",
                        "network": network,
                        "from": "device-a",
                        "method": runner.STREAM_METHOD,
                        "streaming": True,
                        "payload": self.state["stream_payload"],
                        "request_id": "req-stream",
                        "operation_id": 2,
                    }
                elif label == "streaming RPC chunk":
                    frame = {
                        "kind": "rpc_call_stream_chunk",
                        "request_id": "req-stream",
                        "payload": {"sequence": self.chunk, "nonce": self.state["stream_nonce"]},
                    }
                    self.chunk += 1
                elif label == "streaming RPC terminal":
                    frame = {"kind": "rpc_call_stream_end", "request_id": "req-stream", "error": None}
                elif label == "capability replacement":
                    frame = {"kind": "event", "event": {"event_kind": "peer", "kind": "capabilities_changed", "network_id": network, "device_id": "device-a", "capabilities": {"tags": ["application-gateway-e2e-v1"]}}}
                elif label == "capability revocation":
                    frame = {"kind": "event", "event": {"event_kind": "peer", "kind": "capabilities_changed", "network_id": network, "device_id": "device-a", "capabilities": {"tags": []}}}
                else:
                    raise AssertionError(f"unexpected event label: {label}")
                assert callable(predicate)
                assert predicate(frame)
                return frame

        state: dict[str, object] = {"network": "", "payload": None, "stream_payload": None, "stream_nonce": ""}
        processes: list[FakeProcess] = []
        rpc_sockets: list[FakeRpcSocket] = []
        requests: list[dict[str, object]] = []
        clients: dict[str, FakeEventClient] = {}
        terminals: list[FakeProcess] = []

        def fake_popen(*args: object, **kwargs: object) -> FakeProcess:
            del args, kwargs
            process = FakeProcess()
            processes.append(process)
            return process

        def fake_request(control_socket: Path, body: dict[str, object], timeout: float = 5.0) -> dict[str, object]:
            del timeout
            requests.append(body)
            if isinstance(body.get("network"), str):
                state["network"] = body["network"]
            if body.get("op") in {"channel_send_to", "channel_send_reliable"}:
                state["payload"] = body["payload"]
            if body.get("op") == "rpc_call_stream":
                state["stream_payload"] = body["payload"]
                state["stream_nonce"] = body["payload"]["nonce"]
            if body.get("op") == "channel_subscribe" and body.get("client_capability") == "wrong-capability":
                return {"ok": False, "error": "invalid capability"}
            if body.get("op") == "realtime_flow_open":
                return {"ok": True, "data": {"flow_capability": "flow-cap"}}
            if body.get("op") == "peers_list":
                remote = "device-b" if "home-a" in str(control_socket) else "device-a"
                return {"ok": True, "data": {"peers": [{"device_id": remote, "status": "active", "authenticated": True}]}}
            return {"ok": True, "data": {}}

        def fake_socket(*args: object, **kwargs: object) -> FakeRpcSocket:
            del args, kwargs
            socket = FakeRpcSocket(state)
            rpc_sockets.append(socket)
            return socket

        def fake_realtime_pipe(control_socket: Path, body: dict[str, object], timeout: float) -> tuple[FakePipe, FakeBinaryReader]:
            del control_socket, timeout
            if body["direction"] == "inbound":
                return FakePipe(), FakeBinaryReader(runner.encode_realtime_send(b"e2e-audio", b"opaque-realtime-payload"))
            return FakePipe(), FakeBinaryReader(b"")

        def fake_terminate(process: FakeProcess, grace: float) -> dict[str, object]:
            del grace
            terminals.append(process)
            return {"pid": process.pid, "returncode": process.returncode, "forced": False}

        class Args:
            binary = Path(sys.executable)
            artifact_dir = Path()
            resource_grant = COMPLETE_GRANT
            connector_realtime_policy = "enabled"
            timeout = 1.0

        with tempfile.TemporaryDirectory() as temporary:
            Args.artifact_dir = Path(temporary)
            with (
                patch.object(runner.subprocess, "Popen", fake_popen),
                patch.object(runner, "request", fake_request),
                patch.object(runner.socket, "socket", fake_socket),
                patch.object(runner.socket, "AF_UNIX", 1, create=True),
                patch.object(runner.EventClient, "open", classmethod(lambda cls, path, timeout: clients.setdefault(path.parent.name, FakeEventClient(path.parent.name[-1], state)))),
                patch.object(runner, "open_realtime_pipe", fake_realtime_pipe),
                patch.object(runner, "terminate_process", fake_terminate),
                patch.object(runner, "validate_args", lambda args, grant, realtime: runner.validate_grant(grant)),
            ):
                result = runner.run(Args())

        self.assertEqual(len(processes), 2)
        self.assertEqual(len(terminals), 2)
        self.assertTrue(result["observations"][-1]["surface"] == "graceful_terminal")
        self.assertTrue(rpc_sockets and rpc_sockets[0].closed)
        self.assertEqual([body["op"] for body in requests if body["op"] in {"channel_send_to", "channel_send_reliable"}], ["channel_send_to", "channel_send_reliable"])

    def test_mocked_realtime_open_failure_closes_prior_pipe_and_both_daemons(self) -> None:
        # The full production path is covered above; this failure injection
        # specifically proves that a successful first pipe is registered before
        # the second pipe can fail and that process cleanup still runs.
        class FakeProcess:
            next_pid = 42000

            def __init__(self) -> None:
                self.pid = FakeProcess.next_pid
                FakeProcess.next_pid += 1
                self.returncode = 0

        class FakePipe:
            def __init__(self) -> None:
                self.closed = False

            def close(self) -> None:
                self.closed = True

        class FakeReader:
            def __init__(self, lines: list[bytes]) -> None:
                self.lines = iter(lines)
                self.closed = False

            def readline(self, limit: int = -1) -> bytes:
                del limit
                try:
                    return next(self.lines)
                except StopIteration:
                    return b""

            def close(self) -> None:
                self.closed = True

            def __enter__(self) -> "FakeReader":
                return self

            def __exit__(self, *args: object) -> None:
                del args
                self.close()

        class FakeRpcSocket:
            def __init__(self) -> None:
                self.body: dict[str, object] | None = None
                self.closed = False

            def settimeout(self, timeout: float) -> None:
                del timeout

            def connect(self, path: str) -> None:
                del path

            def sendall(self, data: bytes) -> None:
                self.body = json.loads(data.decode("utf-8"))

            def makefile(self, mode: str) -> FakeReader:
                assert mode == "rb" and self.body is not None
                response = {"ok": True, "data": {"response": {"echo": self.body["payload"]}}}
                return FakeReader([json.dumps(response).encode("utf-8") + b"\n"])

            def close(self) -> None:
                self.closed = True

        processes: list[FakeProcess] = []
        rpc_sockets: list[FakeRpcSocket] = []
        closed: list[tuple[FakePipe, FakeReader]] = []
        terminals: list[FakeProcess] = []
        termination_attempts: list[FakeProcess] = []
        calls = 0

        def fake_open(*args: object, **kwargs: object) -> tuple[FakePipe, FakeReader]:
            nonlocal calls
            del args, kwargs
            calls += 1
            if calls == 1:
                pair = (FakePipe(), FakeReader([]))
                closed.append(pair)
                return pair
            raise runner.ContractError("injected realtime open refusal")

        def fake_popen(*args: object, **kwargs: object) -> FakeProcess:
            del args, kwargs
            process = FakeProcess()
            processes.append(process)
            return process

        def fake_terminate(process: FakeProcess, grace: float) -> dict[str, object]:
            del grace
            termination_attempts.append(process)
            if len(termination_attempts) == 1:
                raise RuntimeError("injected terminal cleanup failure")
            return {"pid": process.pid, "returncode": process.returncode, "forced": False}

        def fake_socket(*args: object, **kwargs: object) -> FakeRpcSocket:
            del args, kwargs
            rpc_socket = FakeRpcSocket()
            rpc_sockets.append(rpc_socket)
            return rpc_socket

        class FakeClient:
            client_id = "c"
            capability = "cap"

            def __init__(self, name: str) -> None:
                self.client_id = f"client-{name}"
                self.capability = f"cap-{name}"
                self.chunk = 0

            def close(self) -> None:
                pass

            def until(self, label: str, timeout: float, predicate: object) -> dict[str, object]:
                del timeout, predicate
                if label == "unary RPC inbound":
                    return {"request_id": "req-unary", "operation_id": 1}
                if label == "streaming RPC inbound":
                    return {"request_id": "req-stream", "operation_id": 2}
                if label == "streaming RPC chunk":
                    sequence = self.chunk
                    self.chunk += 1
                    return {"payload": {"sequence": sequence}}
                return {}

        def fake_request(control_socket: Path, body: dict[str, object], timeout: float = 5.0) -> dict[str, object]:
            del timeout
            if body["op"] == "peers_list":
                remote = "device-b" if "home-a" in str(control_socket) else "device-a"
                return {"ok": True, "data": {"peers": [{"device_id": remote, "status": "active", "authenticated": True}]}}
            if body.get("op") == "channel_subscribe" and body.get("client_capability") == "wrong-capability":
                return {"ok": False, "error": "invalid capability"}
            if body["op"] == "realtime_flow_open":
                return {"ok": True, "data": {"flow_capability": "flow-cap"}}
            return {"ok": True, "data": {}}

        class Args:
            binary = Path(sys.executable)
            artifact_dir = Path()
            resource_grant = COMPLETE_GRANT
            connector_realtime_policy = "enabled"
            timeout = 1.0

        with tempfile.TemporaryDirectory() as temporary:
            Args.artifact_dir = Path(temporary)
            with (
                patch.object(runner.subprocess, "Popen", fake_popen),
                patch.object(
                    runner,
                    "request",
                    fake_request,
                ),
                patch.object(runner.socket, "socket", fake_socket),
                patch.object(runner.socket, "AF_UNIX", 1, create=True),
                patch.object(runner.EventClient, "open", classmethod(lambda cls, path, timeout: FakeClient(path.parent.name[-1]))),
                patch.object(runner, "open_realtime_pipe", fake_open),
                patch.object(runner, "terminate_process", lambda process, grace: (terminals.append(process) or fake_terminate(process, grace))),
                patch.object(runner, "validate_args", lambda args, grant, realtime: runner.validate_grant(grant)),
            ):
                with self.assertRaises(runner.ContractError):
                    runner.run(Args())

        self.assertEqual(len(processes), 2)
        self.assertEqual(len(terminals), 2)
        self.assertEqual(len(termination_attempts), 2)
        self.assertEqual(calls, 2)
        self.assertTrue(closed[0][0].closed and closed[0][1].closed)


if __name__ == "__main__":
    unittest.main()
