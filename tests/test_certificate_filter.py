import copy
import json
from pathlib import Path
import sys
from threading import Event
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from client.domain.certificate_filter import filter_duplicate_certificate_keys
from client.domain.commands import ProxyCommand
from client.integrations.eimzo_api import AccessToken, EimzoApiClient


def certificate(name, expiry, *, tin="123456789", pinfl="12345678901234", owner="Owner", organization="Company"):
    parts = [f"cn={owner}", f"o={organization}"]
    if tin:
        parts.append(f"1.2.860.3.16.1.1={tin}")
    if pinfl:
        parts.append(f"1.2.860.3.16.1.2={pinfl}")
    if expiry is not None:
        parts.append(f"validto={expiry}")
    return {"name": name, "alias": ",".join(parts)}


class CertificateFilterTests(unittest.TestCase):
    def test_keeps_latest_expiration_even_when_filename_sequence_is_smaller(self):
        old = certificate("DS1234567899999", "2026.10.28 12:00:00")
        new = certificate("DS1234567890001", "2028.10.28 12:00:00")
        result = filter_duplicate_certificate_keys([old, new])
        self.assertEqual(result.certificates, [new])
        self.assertEqual(result.removed_count, 1)

    def test_arbitrary_names_extensions_and_copy_suffixes_do_not_affect_selection(self):
        for name in ("DS123456789.pfx", "DS123456789 (1)", "DS123456789o0001", "renamed-key"):
            with self.subTest(name=name):
                old = certificate("old-key", "2026.10.28 12:00:00")
                new = certificate(name, "2028.10.28 12:00:00")
                self.assertEqual(filter_duplicate_certificate_keys([old, new]).certificates, [new])

    def test_different_companies_and_signers_remain_separate(self):
        keys = [
            certificate("first", "2028.10.28 12:00:00"),
            certificate("other-company", "2029.10.28 12:00:00", tin="987654321"),
            certificate("other-signer", "2029.10.28 12:00:00", pinfl="98765432101234"),
        ]
        self.assertEqual(filter_duplicate_certificate_keys(keys).certificates, keys)

    def test_personal_and_organization_certificates_remain_separate(self):
        personal = certificate("personal", "2028.10.28 12:00:00", tin=None, organization="")
        business = certificate("business", "2029.10.28 12:00:00")
        self.assertEqual(filter_duplicate_certificate_keys([personal, business]).certificates, [personal, business])

    def test_owner_name_distinguishes_signers_when_pinfl_is_missing(self):
        keys = [certificate("one", "2028.10.28 12:00:00", pinfl=None, owner="One"),
                certificate("two", "2029.10.28 12:00:00", pinfl=None, owner="Two")]
        self.assertEqual(filter_duplicate_certificate_keys(keys).certificates, keys)

    def test_company_name_distinguishes_organizations_when_tin_is_missing(self):
        keys = [certificate("one", "2028.10.28 12:00:00", tin=None, organization="One"),
                certificate("two", "2029.10.28 12:00:00", tin=None, organization="Two")]
        self.assertEqual(filter_duplicate_certificate_keys(keys).certificates, keys)

    def test_unknown_dates_and_identities_are_preserved(self):
        keys = [certificate("valid", "2028.10.28 12:00:00"),
                certificate("missing-date", None), certificate("bad-date", "invalid-date"),
                certificate("unknown-owner", "2029.10.28 12:00:00", tin=None, pinfl=None),
                certificate("bad-tin", "2029.10.28 12:00:00", tin="123", pinfl=None),
                {"name": "unknown-signer", "tin": "123456789", "validto": "2029-01-01"},
                None, "unexpected-entry"]
        self.assertEqual(filter_duplicate_certificate_keys(keys).certificates, keys)

    def test_expired_unique_certificate_is_not_removed_as_duplicate(self):
        key = certificate("only-key", "2020.01.01 00:00:00")
        self.assertEqual(filter_duplicate_certificate_keys([key]).certificates, [key])

    def test_iso_dates_compare_instants_and_explicit_fields_are_supported(self):
        old = {"name": "old", "tin": "123456789", "pinfl": "12345678901234",
               "valid_to": "2028-01-01T12:00:00+05:00"}
        new = {"name": "new", "tin": "123456789", "pinfl": "12345678901234",
               "validto": "2028-01-01T08:00:00Z"}
        self.assertEqual(filter_duplicate_certificate_keys([old, new]).certificates, [new])

    def test_uid_subject_and_case_insensitive_alias_fields_are_supported(self):
        old = {"name": "old", "subject": "UID=123456789,CN=Owner", "validto": "2027-01-01"}
        new = {"name": "new", "alias": "UID=123456789,CN=owner,VALIDTO=2028.01.01 00:00:00"}
        self.assertEqual(filter_duplicate_certificate_keys([old, new]).certificates, [new])

    def test_equal_expirations_keep_first_certificate_and_preserve_list_order(self):
        first = certificate("first", "2028.01.01 00:00:00")
        duplicate = certificate("duplicate", "2028.01.01 00:00:00")
        unrelated = {"name": "unknown"}
        self.assertEqual(filter_duplicate_certificate_keys([first, unrelated, duplicate]).certificates, [first, unrelated])

    def test_does_not_modify_input_or_filter_non_lists(self):
        keys = [certificate("old", "2026.01.01 00:00:00"), certificate("new", "2028.01.01 00:00:00")]
        original = copy.deepcopy(keys)
        filter_duplicate_certificate_keys(keys)
        self.assertEqual(keys, original)
        self.assertIsNone(filter_duplicate_certificate_keys({"certificates": keys}))


class CertificateFilterForwardingTests(unittest.IsolatedAsyncioTestCase):
    async def test_tray_state_applies_to_next_list_response_and_preserves_other_fields(self):
        old = certificate("old.pfx", "2026.01.01 00:00:00")
        new = certificate("new (1).pfx", "2028.01.01 00:00:00")
        payload = {"success": True, "certificates": [old, new], "other": "unchanged"}

        class Response:
            status = 200
            reason = "OK"
            content_type = "application/json"
            charset = "utf-8"

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            async def read(self):
                return json.dumps(payload).encode()

        class Session:
            def request(self, *args, **kwargs):
                return Response()

        state = Event()
        client = EimzoApiClient(session=Session(), api_base_url="http://test", api_path_prefix="",
                                account_name="test", duplicate_key_filter_enabled=state.is_set)
        client._access_token = AccessToken("test-token", None)
        for method in ("list_all_certificates", "list_certificates"):
            for enabled in (False, True, False):
                state.set() if enabled else state.clear()
                cmd = ProxyCommand(plugin="pfx", name=method, has_arguments=method == "list_certificates",
                                   arguments=[], request_id=42, has_request_id=True)
                response = json.loads((await client.forward(cmd)).body)
                self.assertEqual(response["certificates"], [new] if enabled else [old, new])
                self.assertEqual(response["other"], "unchanged")
                self.assertEqual(response["id"], 42)


if __name__ == "__main__":
    unittest.main()
