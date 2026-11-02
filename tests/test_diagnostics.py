import asyncio
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import AsyncMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import aiohttp

from client.diagnostics import enrollment_guid, response_summary, trace_id
from client.domain.commands import ProxyCommand
from client.integrations.eimzo_api import (
    AccessToken, EimzoApiClient, HttpProxyResponse, ProxyResponse, _log_forwarded_api_response,
    _UpstreamRequestError,
)
from client.transport.websocket.server import WebSocketProxyServer

GUID = "d8e5d7ed-eeb0-22c1-fa8f-cd776560858b"


class DiagnosticSummaryTests(unittest.TestCase):
    def test_http_200_failure_preserves_operation_status_and_safe_reason(self):
        response = HttpProxyResponse(200, "OK", ProxyResponse.from_json({
            "success": False, "status": -2026,
            "reason": "Идентификатор процесса GUID уже существует",
        }), elapsed_ms=12)
        with self.assertLogs("client.integrations.eimzo_api", level="INFO") as logs:
            _log_forwarded_api_response(command_label="pki/enroll_pfx_step1", response=response)
        text = logs.output[0]
        self.assertIn("status=200", text)
        self.assertIn('"success":false', text)
        self.assertIn('"status":-2026', text)
        self.assertIn("GUID уже существует", text)
        self.assertIn("elapsed_ms=12", text)
        self.assertTrue(logs.records[0].user_action)

    def test_secrets_and_personal_data_are_omitted_even_in_error_text(self):
        secrets = ["AaBb123456", "PRIVATE-CSR", "PRIVATE-SIGNATURE", "PRIVATE-ALIAS",
                   "PRIVATE-KEY", "PRIVATE-TOKEN", "PERSONAL-NAME", "303389960"]
        payload = {"success": False, "guid": GUID, "status": -9999,
                   "reason": " ".join(secrets), "message": " ".join(secrets),
                   "error": " ".join(secrets), "className": "java.io.IOException",
                   "password": secrets[0], "pkcs10_64": secrets[1], "pkcs7_64": secrets[2],
                   "alias": secrets[3], "privateKey": secrets[4], "token": secrets[5],
                   "subject": secrets[6], "tin": secrets[7], "disk": "/private/path",
                   "stackTrace": [{"declaringClass": "uz.eimzo.app.utils.PkiUtils",
                                   "methodName": "readPFXKeyStore", "lineNumber": 310,
                                   "fileName": secrets[6]}]}
        text = response_summary(json.dumps(payload).encode())
        for secret in secrets + ["/private/path"]:
            self.assertNotIn(secret, text)
        summary = json.loads(text)
        self.assertEqual(summary["guid"], GUID)
        self.assertTrue(summary["password_present"])
        self.assertEqual(summary["pkcs10_64_chars"], len(secrets[1]))
        self.assertEqual(summary["className"], "java.io.IOException")
        self.assertIn("readPFXKeyStore:310", summary["frames"][0])
        self.assertEqual(payload["password"], secrets[0])

    def test_unexpected_field_types_and_non_json_do_not_leak_or_raise(self):
        for payload in ({"success": "PRIVATE", "status": {"secret": "PRIVATE"},
                         "guid": "PRIVATE", "reason": {"secret": "PRIVATE"},
                         "code": "PRIVATE", "className": "PRIVATE", "stackTrace": "PRIVATE"},
                        ["PRIVATE"], None):
            with self.subTest(payload=payload):
                self.assertNotIn("PRIVATE", response_summary(json.dumps(payload).encode()))
        for body in (b"<html>PRIVATE</html>", b"\xffPRIVATE", b""):
            self.assertNotIn("PRIVATE", response_summary(body, "invalid-encoding"))

    def test_guid_only_comes_from_enrollment_and_must_be_a_uuid(self):
        for name in ("enroll_pfx_step1", "enroll_pfx_step2"):
            self.assertEqual(enrollment_guid(ProxyCommand(name, "pki", [GUID, "SECRET"])), GUID)
        self.assertIsNone(enrollment_guid(ProxyCommand("load_key", "pfx", [GUID])))
        self.assertIsNone(enrollment_guid(ProxyCommand("enroll_pfx_step1", "pki", ["SECRET"])))


class Socket:
    def __init__(self, *, fail=False):
        self.fail = fail
        self.sent = []
        self.closed = False

    async def send(self, data):
        if self.fail:
            self.fail = False
            raise RuntimeError("PRIVATE-SEND-ERROR")
        self.sent.append(data)

    async def close(self, **kwargs):
        self.closed = True


def server(proxy):
    return WebSocketProxyServer(config=None, endpoint_proxy=proxy,
        server_cert_path=Path("unused"), server_key_path=Path("unused"),
        certificate_rotation_event=asyncio.Event())


class DiagnosticFlowTests(unittest.IsolatedAsyncioTestCase):
    async def test_enrollment_api_and_socket_logs_share_trace_and_preserve_payload(self):
        payload = {"success": True, "guid": GUID, "password": "PRIVATE-PASSWORD",
                   "pkcs10_64": "PRIVATE-CSR", "pkcs7_64": "PRIVATE-SIGNATURE"}
        class Response:
            status, reason, content_type, charset = 200, "OK", "application/json", "utf-8"
            def __init__(self, value):
                self.body = json.dumps(value).encode()
            async def __aenter__(self):
                return self
            async def __aexit__(self, *args):
                pass
            async def read(self):
                return self.body
        class Session:
            responses = [Response({"success": True}), Response(payload)]
            def request(self, *args, **kwargs):
                return self.responses.pop(0)
        prompts = type("Prompts", (), {"request_new_pfx_password": AsyncMock(return_value="PRIVATE-PASSWORD")})()
        client = EimzoApiClient(session=Session(), api_base_url="http://test", api_path_prefix="",
                                account_name="test", prompt_service=prompts)
        client._access_token = AccessToken("PRIVATE-TOKEN", None)
        sock = Socket()
        with self.assertLogs("client", level="INFO") as logs:
            await server(client)._handle_message(sock, json.dumps({"plugin": "pki",
                "name": "enroll_pfx_step1", "arguments": [GUID, "PRIVATE-SUBJECT"]}),
                request_path="/", origin="https://site.uz", remote_address=None)
        self.assertEqual(json.loads(sock.sent[0]), payload)
        events = [line for line in logs.output if "E-IMZO API server response." in line
                  or "WebSocket response sent." in line]
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].split("trace_id=")[1].split()[0],
                         events[1].split("trace_id=")[1].split()[0])
        for event in events:
            self.assertIn('"success":true', event)
            self.assertIn(GUID, event)
            self.assertIn("elapsed_ms=", event)
        self.assertNotIn("PRIVATE", "\n".join(logs.output))

    async def test_parallel_requests_have_distinct_traces_and_preserve_responses(self):
        traces = []
        body = ProxyResponse.from_json({"success": True, "guid": GUID, "password": "PRIVATE"})
        class Proxy:
            async def forward(self, command, **kwargs):
                first = trace_id.get()
                await asyncio.sleep(0)
                traces.append((first, trace_id.get()))
                return body
        handler = server(Proxy())
        sockets = [Socket(), Socket()]
        raw = json.dumps({"plugin": "pki", "name": "enroll_pfx_step1", "arguments": [GUID]})
        with self.assertLogs("client.transport.websocket.server", level="INFO") as logs:
            await asyncio.gather(*(handler._handle_message(sock, raw,
                request_path="/", origin="https://site.uz", remote_address=None) for sock in sockets))
        self.assertEqual(len({first for first, _ in traces}), 2)
        self.assertTrue(all(first == second for first, second in traces))
        self.assertEqual(trace_id.get(), "-")
        self.assertNotIn("PRIVATE", "\n".join(logs.output))
        for sock in sockets:
            self.assertEqual(sock.sent, [body.to_websocket_payload()])
            self.assertTrue(sock.closed)
        self.assertEqual(sum("WebSocket response sent." in line for line in logs.output), 2)
        for first, _ in traces:
            self.assertEqual(sum(first in line for line in logs.output), 2)

    async def test_failed_send_reports_stage_and_exception_without_success_event(self):
        class Proxy:
            async def forward(self, command, **kwargs):
                return ProxyResponse.from_json({"success": True})
        with self.assertLogs("client.transport.websocket.server", level="INFO") as logs:
            await server(Proxy())._handle_message(Socket(fail=True), '{"name":"version","id":123}',
                request_path="/", origin="https://site.uz", remote_address=None)
        text = "\n".join(logs.output)
        self.assertIn("stage=send_response", text)
        self.assertIn("error_type=RuntimeError", text)
        self.assertNotIn("WebSocket response sent.", text)
        self.assertNotIn("PRIVATE-SEND-ERROR", text)
        self.assertEqual(trace_id.get(), "-")

    async def test_transport_timeout_records_type_and_duration_without_exception_message(self):
        class Session:
            def request(self, *args, **kwargs):
                raise aiohttp.ClientConnectionError("PRIVATE-TRANSPORT-ERROR")
        client = EimzoApiClient(session=Session(), api_base_url="http://test", api_path_prefix="",
                                account_name="test")
        with self.assertLogs("client.integrations.eimzo_api", level="WARNING") as logs:
            with self.assertRaises(_UpstreamRequestError):
                await client._request(method="POST", endpoint_url="http://test/pki/enroll_pfx_step1",
                                      headers={"Authorization": "PRIVATE-TOKEN"})
        text = "\n".join(logs.output)
        self.assertIn("error_type=ClientConnectionError", text)
        self.assertIn("elapsed_ms=", text)
        self.assertNotIn("PRIVATE", text)
        self.assertTrue(logs.records[0].user_action)
