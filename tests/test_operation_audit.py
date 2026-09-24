import base64
import json
from pathlib import Path
import tempfile
import unittest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class FakeResponse:
    status = 200
    reason = "OK"
    content_type = "application/json"
    charset = "utf-8"

    def __init__(self, payload):
        self.payload = payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def read(self):
        return json.dumps(self.payload).encode()


def _json_response(payload):
    return FakeResponse(payload)


def _make_jwt(exp):
    payload = base64.urlsafe_b64encode(json.dumps({"exp": exp}).encode()).decode().rstrip("=")
    return "e30." + payload + ".test"


class FakeClientSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def request(self, method, url, **kwargs):
        self.requests.append(kwargs)
        return self.responses.pop(0)


class FakePromptService:
    def __init__(self, passwords=(), confirmations=()):
        self.passwords = list(passwords)
        self.confirmations = list(confirmations)

    async def request_password(self, **kwargs):
        return self.passwords.pop(0)

    async def confirm_sensitive_operation(self, **kwargs):
        return self.confirmations.pop(0)

from client.domain.commands import ProxyCommand
from client.integrations.eimzo_api import EimzoApiClient
from client.system.audit_identity import installation_id


class OperationAuditTests(unittest.IsolatedAsyncioTestCase):
    async def test_exact_key_mapping_across_origins_and_both_operations(self):
        session = FakeClientSession([
            _json_response({"token": _make_jwt(exp=4_000_000_000)}),
            _json_response({"success": True, "keyId": "key-a"}),
            _json_response({"success": True, "keyId": "key-b"}),
            _json_response({"success": True}),
            _json_response({"success": True}),
        ])
        client = EimzoApiClient(session=session, api_base_url="http://test", api_path_prefix="",
            account_name="user", audit_client_id="installation-1",
            prompt_service=FakePromptService(passwords=["secret"], confirmations=[True, True]))
        for key_name in ("DS1234567890001", "DS1234567890002"):
            await client.forward(ProxyCommand(plugin="pfx", name="load_key", has_arguments=True,
                arguments=["/media/", "", key_name, "cn=Owner,o=Company,uid=123456789"]), origin="https://first.uz")
        await client.forward(ProxyCommand(plugin="pkcs7", name="create_pkcs7", has_arguments=True,
            arguments=["secret-document", "key-a", "no"]), origin="https://second.uz")
        await client.forward(ProxyCommand(plugin="x509", name="get_certificate_chain", has_arguments=True,
            arguments=["key-b"]), origin="https://third.uz")
        first, second = [json.loads(base64.b64decode(item["headers"]["X-ATB-Audit"])) for item in session.requests[-2:]]
        self.assertEqual(first["key_name"], "DS1234567890001")
        self.assertEqual(second["key_name"], "DS1234567890002")
        self.assertEqual(first["origin"], "https://second.uz")
        self.assertEqual(second["origin"], "https://third.uz")
        self.assertEqual(first["client_id"], "installation-1")
        self.assertNotIn("secret", str(first))
        for item in session.requests[:-2]:
            self.assertNotIn("X-ATB-Audit", item["headers"])

    async def test_failed_load_does_not_overwrite_mapping(self):
        session = FakeClientSession([
            _json_response({"token": _make_jwt(exp=4_000_000_000)}),
            _json_response({"success": True, "keyId": "key-a"}),
            _json_response({"success": False, "keyId": "key-a"}),
        ])
        client = EimzoApiClient(session=session, api_base_url="http://test", api_path_prefix="",
            account_name="user", prompt_service=FakePromptService(passwords=["secret"]))
        for name in ("DS1234567890001", "DS9876543210001"):
            await client.forward(ProxyCommand(plugin="pfx", name="load_key", has_arguments=True,
                arguments=["/media/", "", name, "cn=Owner"]))
        context = client._audit_context(ProxyCommand(plugin="x509", name="get_certificate_chain",
            has_arguments=True, arguments=["key-a"]), None)
        self.assertEqual(context["key_name"], "DS1234567890001")

    async def test_unknown_key_is_not_guessed(self):
        client = EimzoApiClient(session=None, api_base_url="http://test", api_path_prefix="",
                               account_name="user", prompt_service=FakePromptService())
        client._audit_keys["known"] = "DS123"
        context = client._audit_context(ProxyCommand(plugin="pkcs7", name="create_pkcs7",
            has_arguments=True, arguments=["data", "unknown", "no"]), "https://site.uz")
        self.assertNotIn("key_name", context)


class InstallationIdentityTests(unittest.TestCase):
    def test_id_survives_restart_and_differs_between_installations(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = installation_id(Path(tmp) / "one")
            self.assertIsNotNone(first)
            self.assertEqual(first, installation_id(Path(tmp) / "one"))
            self.assertNotEqual(first, installation_id(Path(tmp) / "two"))
