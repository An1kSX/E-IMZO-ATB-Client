import asyncio
import base64
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import aiohttp
from websockets.legacy.client import connect
from websockets.legacy.server import serve
from websockets.datastructures import Headers

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from client.domain.commands import ProxyCommand
from client.integrations.eimzo_api import AccessToken, EimzoApiClient
from client.transport.websocket.messages import parse_proxy_command
from client.transport.websocket.server import WebSocketProxyServer
from client.ui.prompts import SensitiveOperationConfirmation, _show_info_dialog


class Response:
    reason = "Test response"
    content_type = "application/json"
    charset = "utf-8"

    def __init__(self, status=200, payload=None, body=None):
        self.status = status
        self.body = body if body is not None else json.dumps(payload).encode()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def read(self):
        return self.body


def denied(code="ORIGIN_ACCESS_DENIED", origin="https://blocked.uz", status=403):
    return Response(status, {"detail": {"code": code, "origin": origin}})


class Session:
    def __init__(self, responses, events):
        self.responses = list(responses)
        self.events = events
        self.calls = []

    def request(self, method, url, **kwargs):
        self.events.append(url.rsplit("/", 1)[-1])
        self.calls.append((method, url, kwargs))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class Prompts:
    def __init__(self, events):
        self.events = events
        self.errors = []
        self.block_dialog = None

    async def request_password(self, **kwargs):
        self.events.append("login_password")
        return "login-secret"

    async def confirm_sensitive_operation(self, **kwargs):
        self.events.append("key_password")
        return SensitiveOperationConfirmation(approved=True, manual_password="key-secret")

    async def request_new_pfx_password(self, **kwargs):
        self.events.append("new_key_password")
        return "new-key-secret"

    async def show_access_error(self, *, message):
        self.errors.append(message)
        if self.block_dialog is not None:
            await self.block_dialog.wait()


def command(plugin="pfx", name="load_key", arguments=None, request_id=7):
    return ProxyCommand(plugin=plugin, name=name, arguments=arguments or [], has_arguments=True,
                        request_id=request_id, has_request_id=True)


class OriginAccessTests(unittest.IsolatedAsyncioTestCase):
    def make_client(self, responses, *, authenticated=True, account_name="user"):
        events = []
        prompts = Prompts(events)
        session = Session(responses, events)
        client = EimzoApiClient(session=session, api_base_url="http://test", api_path_prefix="remote",
                                account_name=account_name, audit_client_id="installation", prompt_service=prompts)
        if authenticated:
            client._access_token = AccessToken("test-jwt", None)
        client._key_identity_store.remember(key_id="loaded-key", key_subject="uid=123456789")
        return client, session, prompts, events

    async def settle_dialogs(self, client):
        await asyncio.gather(*list(client._access_error_tasks.values()))

    async def test_login_precedes_access_check_and_key_password(self):
        client, session, prompts, events = self.make_client([
            Response(payload={"token": "test-jwt"}), Response(payload={"success": True}),
            Response(payload={"success": True}),
        ], authenticated=False)
        result = await client.forward(command("pkcs7", "create_pkcs7", ["document", "loaded-key"]),
                                      origin="https://site.uz")
        self.assertTrue(json.loads(result.body)["success"])
        self.assertEqual(events, ["login_password", "login", "check_access", "key_password", "create_pkcs7"])
        preflight = session.calls[1]
        self.assertEqual(preflight[:2], ("POST", "http://test/remote/auth/check_access"))
        self.assertNotIn("json", preflight[2])
        self.assertEqual(preflight[2]["headers"], session.calls[2][2]["headers"])

    async def test_all_key_operations_use_preflight_and_original_origin(self):
        operations = [
            ("pkcs7", "create_pkcs7"), ("pkcs7", "append_pkcs7_attached"),
            ("x509", "get_certificate_chain"), ("pfx", "load_key"), ("pfx", "verify_password"),
            ("pfx", "change_password"), ("pfx", "save_pfx"), ("pfx", "save_temporary_pfx"),
            ("pki", "enroll_pfx_step1"), ("pki", "enroll_pfx_step2"),
        ]
        for plugin, name in operations:
            with self.subTest(plugin=plugin, name=name):
                client, session, prompts, events = self.make_client([
                    Response(payload={"success": True}), Response(payload={"success": True}),
                ])
                result = await client.forward(command(plugin, name, {"origin": "https://spoofed.uz"}),
                                              origin="https://САЙТ.uz:8443")
                self.assertTrue(json.loads(result.body)["success"])
                self.assertEqual(len(session.calls), 2)
                for method, url, kwargs in session.calls:
                    self.assertEqual(method, "POST")
                    headers = kwargs["headers"]
                    self.assertEqual(headers["Authorization"], "Bearer test-jwt")
                    self.assertEqual(set(headers), {"Authorization", "X-ATB-Audit"})
                    audit = json.loads(base64.b64decode(headers["X-ATB-Audit"]))
                    self.assertEqual(audit["origin"], "https://САЙТ.uz:8443")
                    self.assertEqual(audit["client_id"], "installation")

    async def test_denials_and_invalid_preflight_never_open_key_prompt_or_send_operation(self):
        cases = [
            (denied(), "ORIGIN_ACCESS_DENIED", "https://blocked.uz"),
            (denied("ROLE_REQUIRED", None), "ROLE_REQUIRED", "Вам не назначена роль"),
            (denied("ORIGIN_REQUIRED", None), "ORIGIN_REQUIRED", "Не удалось определить сайт"),
            (denied("ORIGIN_INVALID", None), "ORIGIN_INVALID", "некорректный адрес"),
            (denied("ACCESS_SERVICE_UNAVAILABLE", None, 503), "ACCESS_SERVICE_UNAVAILABLE", "позже"),
            (denied("UNKNOWN"), "ACCESS_CHECK_FAILED", "Операция отменена"),
            (denied({"malformed": True}), "ACCESS_CHECK_FAILED", "Операция отменена"),
            (Response(403, body=b"not-json"), "ACCESS_CHECK_FAILED", "Операция отменена"),
            (Response(404, {}), "ACCESS_CHECK_FAILED", "Операция отменена"),
            (Response(302, {}), "ACCESS_CHECK_FAILED", "Операция отменена"),
            (Response(200, {"success": False}), "ACCESS_CHECK_FAILED", "Операция отменена"),
            (Response(200, {"success": 1}), "ACCESS_CHECK_FAILED", "Операция отменена"),
            (Response(204, {"success": True}), "ACCESS_CHECK_FAILED", "Операция отменена"),
            (Response(200, body=b"garbage"), "ACCESS_CHECK_FAILED", "Операция отменена"),
            (aiohttp.ClientConnectionError("network failed"), "ACCESS_SERVICE_UNAVAILABLE", "позже"),
            (asyncio.TimeoutError(), "ACCESS_SERVICE_UNAVAILABLE", "позже"),
        ]
        for response, code, message in cases:
            with self.subTest(code=code, response=response):
                client, session, prompts, events = self.make_client([response])
                result = json.loads((await client.forward(command("pkcs7", "create_pkcs7",
                                                                  ["document", "loaded-key"]))).body)
                await self.settle_dialogs(client)
                self.assertEqual(result["code"], code)
                self.assertEqual(result["id"], 7)
                self.assertFalse(result["success"])
                self.assertIn(message, result["message"])
                self.assertEqual(events, ["check_access"])
                self.assertEqual(prompts.errors, [result["message"]])

    async def test_null_denial_origin_does_not_display_null(self):
        client, _, _, _ = self.make_client([denied(origin=None)])
        result = json.loads((await client.forward(command())).body)
        self.assertIn("на этом сайте", result["message"])
        await self.settle_dialogs(client)

    async def test_no_origin_or_admin_exception_is_inferred_locally(self):
        for origin in (None, "null", "garbage", "http://localhost:3000", "https://allowed.uz/" + "x" * 1100):
            for account in ("user", "admin"):
                with self.subTest(origin=origin, account=account):
                    client, session, _, _ = self.make_client([
                        Response(payload={"success": True}), Response(payload={"success": True}),
                    ], account_name=account)
                    result = await client.forward(command(), origin=origin)
                    self.assertTrue(json.loads(result.body)["success"])
                    audit = json.loads(base64.b64decode(session.calls[0][2]["headers"]["X-ATB-Audit"]))
                    self.assertEqual(audit.get("origin"), origin)

    async def test_revocation_after_preflight_and_with_cached_confirmation(self):
        client, session, prompts, events = self.make_client([
            Response(payload={"success": True}), denied("ROLE_REQUIRED"), denied("ROLE_REQUIRED"),
        ])
        client._sensitive_confirmation_auto_approve_until = float("inf")
        for request_id in (1, 2):
            result = json.loads((await client.forward(command("pkcs7", "create_pkcs7",
                                                              ["document", "loaded-key"], request_id))).body)
            self.assertEqual(result["code"], "ROLE_REQUIRED")
            self.assertEqual(result["id"], request_id)
        await self.settle_dialogs(client)
        self.assertEqual(events, ["check_access", "create_pkcs7", "check_access"])
        self.assertEqual(len(prompts.errors), 1)

    async def test_each_operation_checks_again_and_role_change_requires_no_relogin(self):
        client, _, prompts, events = self.make_client([
            Response(payload={"success": True}), Response(payload={"success": True}), denied("ROLE_REQUIRED"),
        ])
        self.assertTrue(json.loads((await client.forward(command())).body)["success"])
        self.assertEqual(json.loads((await client.forward(command())).body)["code"], "ROLE_REQUIRED")
        await self.settle_dialogs(client)
        self.assertEqual(events, ["check_access", "load_key", "check_access"])

    async def test_certificate_listing_and_version_have_no_preflight_but_handle_role_denial(self):
        for cmd in (ProxyCommand(name="version"), ProxyCommand(plugin="pfx", name="list_all_certificates")):
            client, session, prompts, events = self.make_client([denied("ROLE_REQUIRED")])
            result = json.loads((await client.forward(cmd)).body)
            await self.settle_dialogs(client)
            self.assertEqual(result["code"], "ROLE_REQUIRED")
            self.assertEqual(events, [cmd.name])
            self.assertEqual(len(session.calls), 1)

    async def test_401_reauthenticates_and_rechecks_before_key_prompt(self):
        client, session, prompts, events = self.make_client([
            Response(401, {}), Response(payload={"token": "fresh-token"}),
            denied("ROLE_REQUIRED"),
        ])
        result = json.loads((await client.forward(command())).body)
        await self.settle_dialogs(client)
        self.assertEqual(result["code"], "ROLE_REQUIRED")
        self.assertEqual(events, ["check_access", "login_password", "login", "check_access"])
        self.assertEqual(session.calls[-1][2]["headers"]["Authorization"], "Bearer fresh-token")

    async def test_operation_401_rechecks_after_relogin_and_does_not_retry_denial(self):
        client, session, _, events = self.make_client([
            Response(payload={"success": True}), Response(401, {}),
            Response(payload={"token": "fresh-token"}), denied(),
        ])
        result = json.loads((await client.forward(command())).body)
        await self.settle_dialogs(client)
        self.assertEqual(result["code"], "ORIGIN_ACCESS_DENIED")
        self.assertEqual(events, ["check_access", "load_key", "login_password", "login", "check_access"])

    async def test_repeated_401_stops_and_invalidates_session(self):
        client, _, _, events = self.make_client([
            Response(401, {}), Response(payload={"token": "fresh-token"}), Response(401, {}),
        ])
        result = json.loads((await client.forward(command())).body)
        await self.settle_dialogs(client)
        self.assertEqual(result["code"], "SESSION_EXPIRED")
        self.assertIsNone(client._access_token)
        self.assertEqual(events, ["check_access", "login_password", "login", "check_access"])

    async def test_operation_errors_preserve_password_error_and_reject_malformed_response(self):
        for response, expected_code in ((Response(400, {"success": False, "message": "Wrong key password"}), None),
                                        (Response(200, body=b"broken-json"), "ACCESS_CHECK_FAILED")):
            with self.subTest(expected_code=expected_code):
                client, _, prompts, events = self.make_client([Response(payload={"success": True}), response])
                result = json.loads((await client.forward(command())).body)
                await self.settle_dialogs(client)
                self.assertFalse(result["success"])
                self.assertEqual(result.get("code"), expected_code)
                if expected_code is None:
                    self.assertEqual(result["message"], "Wrong key password")
                    self.assertEqual(prompts.errors, [])
                self.assertEqual(events, ["check_access", "load_key"])

    async def test_apikey_localhost_arguments_are_not_used_as_origin(self):
        client, session, _, _ = self.make_client([Response(payload={"success": True})])
        await client.forward(command(None, "apikey", ["localhost", "api-key"]), origin="https://actual.uz")
        self.assertEqual(session.calls[0][2]["json"], ["localhost", "api-key"])
        audit = json.loads(base64.b64decode(session.calls[0][2]["headers"]["X-ATB-Audit"]))
        self.assertEqual(audit["origin"], "https://actual.uz")

    async def test_duplicate_origin_is_not_replaced_with_first_allowed_origin(self):
        client, _, _, _ = self.make_client([])
        server = WebSocketProxyServer(config=None, endpoint_proxy=client, server_cert_path=Path("unused"),
            server_key_path=Path("unused"), certificate_rotation_event=asyncio.Event())
        headers = Headers([("Origin", "https://allowed.uz"), ("Origin", "https://blocked.uz")])
        await server._process_opening_handshake_request("/", headers)
        self.assertEqual(headers.get_all("Origin"), ["https://allowed.uz", "https://blocked.uz"])
        self.assertNotEqual(server._resolve_request_origin(SimpleNamespace(request_headers=headers)), "https://allowed.uz")

    async def test_repeated_denials_finish_with_unique_ids_while_one_dialog_is_open(self):
        client, _, prompts, _ = self.make_client([denied() for _ in range(5)])
        prompts.block_dialog = asyncio.Event()
        results = await asyncio.wait_for(asyncio.gather(*[
            client.forward(command(request_id=index)) for index in range(5)
        ]), timeout=2)
        await asyncio.sleep(0)
        self.assertEqual([json.loads(result.body)["id"] for result in results], list(range(5)))
        self.assertEqual(len(prompts.errors), 1)
        prompts.block_dialog.set()
        await self.settle_dialogs(client)

    async def test_notification_cooldown_does_not_cache_access_decision(self):
        client, session, prompts, _ = self.make_client([denied(), denied(), denied()])
        now = [100.0]
        client._clock = lambda: now[0]
        await client.forward(command())
        await self.settle_dialogs(client)
        await client.forward(command())
        await self.settle_dialogs(client)
        self.assertEqual(len(prompts.errors), 1)
        now[0] += 3
        await client.forward(command())
        await self.settle_dialogs(client)
        self.assertEqual(len(prompts.errors), 2)
        self.assertEqual(len(session.calls), 3)

    async def test_unexpected_client_failure_finishes_websocket_request_with_original_id(self):
        class BrokenProxy:
            async def forward(self, *args, **kwargs):
                raise RuntimeError("sensitive request must not be logged")

        class Socket:
            async def send(self, data):
                self.payload = json.loads(data)

            async def close(self, **kwargs):
                self.closed = True

        server = WebSocketProxyServer(config=None, endpoint_proxy=BrokenProxy(), server_cert_path=Path("unused"),
            server_key_path=Path("unused"), certificate_rotation_event=asyncio.Event())
        websocket = Socket()
        with self.assertLogs("client.transport.websocket.server", level="ERROR") as captured:
            await server._handle_message(websocket, '{"name":"version","id":"original"}',
                                         origin="https://site.uz", request_path="/", remote_address=None)
        self.assertFalse(websocket.payload["success"])
        self.assertEqual(websocket.payload["id"], "original")
        self.assertTrue(websocket.closed)
        self.assertNotIn("sensitive request", "\n".join(captured.output))

    async def test_documents_passwords_tokens_and_response_bodies_are_not_logged(self):
        secrets = ["PRIVATE-DOCUMENT", "PRIVATE-SIGNATURE", "PRIVATE-KEY", "test-jwt", "key-secret"]
        client, _, _, _ = self.make_client([
            Response(payload={"success": True}), Response(403, {"detail": {"code": "UNKNOWN",
            "message": " ".join(secrets), "data": secrets}}),
        ])
        with self.assertLogs("client.integrations.eimzo_api", level="INFO") as captured:
            await client.forward(command("pkcs7", "create_pkcs7", [secrets[0], "loaded-key"]))
            await self.settle_dialogs(client)
        for secret in secrets:
            self.assertNotIn(secret, "\n".join(captured.output))

    async def test_parallel_websockets_keep_their_handshake_origin(self):
        client, session, prompts, events = self.make_client([])
        arrivals = asyncio.Event()
        origins = []

        class BarrierResponse(Response):
            async def read(self):
                await arrivals.wait()
                return self.body

        def request(method, url, **kwargs):
            audit = json.loads(base64.b64decode(kwargs["headers"]["X-ATB-Audit"]))
            origins.append(audit["origin"])
            if len(origins) == 2:
                arrivals.set()
            return BarrierResponse(403, {"detail": {"code": "ORIGIN_ACCESS_DENIED", "origin": audit["origin"]}})

        session.request = request
        server = WebSocketProxyServer(config=SimpleNamespace(matches_websocket_path=lambda path: path == "/"),
            endpoint_proxy=client, server_cert_path=Path("unused"), server_key_path=Path("unused"),
            certificate_rotation_event=asyncio.Event())
        async with serve(server._handle_connection, "127.0.0.1", 0,
                         process_request=server._process_opening_handshake_request) as listener:
            port = listener.sockets[0].getsockname()[1]

            async def send(site, request_id):
                async with connect(f"ws://127.0.0.1:{port}/", origin=site) as websocket:
                    await websocket.send(json.dumps({"plugin": "pfx", "name": "load_key", "id": request_id,
                                                    "arguments": {"origin": "https://spoofed.uz"}}))
                    return json.loads(await websocket.recv())

            results = await asyncio.wait_for(asyncio.gather(send("https://a.uz", "a"), send("https://b.uz", "b")), 5)
        await self.settle_dialogs(client)
        self.assertCountEqual(origins, ["https://a.uz", "https://b.uz"])
        for result, site in zip(results, ("a", "b")):
            self.assertEqual(result["id"], site)
            self.assertIn(f"https://{site}.uz", result["message"])


class AccessDialogTests(unittest.TestCase):
    def test_dialog_is_owned_topmost_and_displays_plain_text(self):
        message = "Нет доступа: <b>https://site.uz</b>"
        with patch("tkinter.Tk") as root_factory, patch("tkinter.messagebox.showinfo") as showinfo:
            _show_info_dialog(title="E-IMZO", message=message)
            root = root_factory.return_value
            root.attributes.assert_called_once_with("-topmost", True)
            showinfo.assert_called_once_with(title="E-IMZO", message=message, parent=root)
            root.destroy.assert_called_once()

    def test_parser_preserves_request_id(self):
        cmd = parse_proxy_command('{"id":0,"name":"version"}')
        self.assertEqual(cmd.request_id, 0)
        self.assertTrue(cmd.has_request_id)
        self.assertFalse(parse_proxy_command('{"name":"version"}').has_request_id)


if __name__ == "__main__":
    unittest.main()
