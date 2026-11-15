"""The three mail sources against mocked servers (no network, no real credentials):
Microsoft Graph (token, folder, paging, raw message, error hints), Gmail API (signed service-account token,
label, paging, raw message), IMAP settings checks, and the MailState skip-list."""
import base64
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import mail_sources as ms  # noqa: E402

RAW = b"From: reports@shadowserver.org\r\nSubject: test\r\nMessage-ID: <a@b>\r\n\r\nhttps://dl.shadowserver.org/abc\r\n"


class Resp:
    def __init__(self, status=200, body=None, content=b""):
        self.status_code, self._body, self.content, self.headers = status, body, content, {}

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


class GraphTest(unittest.TestCase):
    ENV = {"MAIL_PROVIDER": "microsoft_graph", "MS_TENANT_ID": "t-1", "MS_CLIENT_ID": "c-1",
           "MS_CLIENT_SECRET": "s-1", "MS_MAILBOX": "csirt@example.org", "MS_FOLDER": "Shadowserver"}

    def test_flow(self):
        calls = []

        def call(self_, method, url, what, **kw):
            calls.append((method, url, kw.get("params")))
            if "login.microsoftonline.com/t-1/oauth2/v2.0/token" in url:
                assert kw["data"]["grant_type"] == "client_credentials" and kw["data"]["client_secret"] == "s-1"
                return Resp(body={"access_token": "tok", "expires_in": 3600})
            assert kw["headers"]["Authorization"] == "Bearer tok"
            if url.endswith("/mailFolders") and "displayName eq 'Shadowserver'" in kw["params"]["$filter"]:
                return Resp(body={"value": [{"id": "F1"}]})
            if url.endswith("/mailFolders/F1/messages"):
                assert kw["params"]["$filter"].startswith("receivedDateTime ge ")
                return Resp(body={"value": [{"id": "m1", "internetMessageId": "<a@b>"}],
                                  "@odata.nextLink": "https://graph.microsoft.com/v1.0/next"})
            if url == "https://graph.microsoft.com/v1.0/next":
                return Resp(body={"value": [{"id": "m2", "internetMessageId": None}]})
            if url.endswith("/messages/m1/$value"):
                return Resp(content=RAW)
            raise AssertionError(url)

        with mock.patch.object(ms._Http, "__init__", lambda self_: None), mock.patch.object(ms._Http, "call", call):
            src = ms.make_source(self.ENV)
            items = src.list(1)
            # keyed by the mailbox's own id, never the sender-written internetMessageId; the old key kept as legacy
            self.assertEqual(items, [("graph:id:m1", "m1"), ("graph:id:m2", "m2")])
            self.assertEqual(src.legacy, {"graph:id:m1": "graph:<a@b>", "graph:id:m2": "graph:m2"})
            self.assertEqual(list(src.fetch(items[:1])), [("graph:id:m1", RAW)])
            self.assertEqual(sum(1 for c in calls if "oauth2" in c[1]), 1, "token is reused")
            self.assertIn("csirt%40example.org", calls[1][1])

    def test_errors_explained(self):
        def bad_secret(self_, method, url, what, **kw):
            return Resp(400, {"error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret provided."})

        with mock.patch.object(ms._Http, "__init__", lambda self_: None), mock.patch.object(ms._Http, "call", bad_secret):
            with self.assertRaisesRegex(ms.MailSourceError, "Value, not its Secret ID"):
                ms.make_source(self.ENV).list(1)

        def blocked(self_, method, url, what, **kw):       # Microsoft's real answer when Conditional Access blocks the app
            return Resp(400, {"error": "invalid_grant", "error_description": "AADSTS53003: Access has been blocked by "
                                                                              "Conditional Access policies."})

        with mock.patch.object(ms._Http, "__init__", lambda self_: None), mock.patch.object(ms._Http, "call", blocked):
            with self.assertRaisesRegex(ms.MailSourceError, "Conditional Access policy of your tenant"):
                ms.make_source(self.ENV).list(1)

        def forbidden(self_, method, url, what, **kw):
            if "oauth2" in url:
                return Resp(body={"access_token": "tok"})
            return Resp(403, {"error": {"code": "ErrorAccessDenied", "message": "Access is denied."}})

        with mock.patch.object(ms._Http, "__init__", lambda self_: None), mock.patch.object(ms._Http, "call", forbidden):
            with self.assertRaisesRegex(ms.MailSourceError, "Mail.Read"):
                ms.make_source({**self.ENV, "MS_FOLDER": "inbox"}).list(1)

    def test_missing_settings(self):
        with self.assertRaisesRegex(ms.MailSourceError, "MS_CLIENT_SECRET"):
            ms.make_source({k: v for k, v in self.ENV.items() if k != "MS_CLIENT_SECRET"})


class GmailTest(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()).decode()
        self.dir = tempfile.TemporaryDirectory()
        self.keyfile = Path(self.dir.name) / "sa.json"
        self.keyfile.write_text(json.dumps({"client_email": "lg@proj.iam.gserviceaccount.com", "private_key": pem,
                                            "token_uri": "https://oauth2.googleapis.com/token"}))
        self.env = {"MAIL_PROVIDER": "gmail_api", "GMAIL_SERVICE_ACCOUNT_FILE": str(self.keyfile),
                    "GMAIL_USER": "csirt@example.org", "GMAIL_LABEL": "Shadowserver"}

    def tearDown(self):
        self.dir.cleanup()

    def test_flow(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        pub = self.key.public_key()

        def unb64(s):
            return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

        def call(self_, method, url, what, **kw):
            if url == "https://oauth2.googleapis.com/token":
                h, c, sig = kw["data"]["assertion"].split(".")
                pub.verify(unb64(sig), f"{h}.{c}".encode(), padding.PKCS1v15(), hashes.SHA256())   # raises if bad
                claims = json.loads(unb64(c))
                assert claims["sub"] == "csirt@example.org" and claims["scope"].endswith("gmail.readonly")
                assert claims["exp"] - claims["iat"] == 3600 and abs(claims["iat"] - time.time()) < 60
                return Resp(body={"access_token": "gtok", "expires_in": 3600})
            assert kw["headers"]["Authorization"] == "Bearer gtok"
            if url.endswith("/labels"):
                return Resp(body={"labels": [{"id": "INBOX", "name": "INBOX"}, {"id": "Label_7", "name": "Shadowserver"}]})
            if url.endswith("/messages") and kw["params"].get("pageToken") is None:
                assert kw["params"]["labelIds"] == "Label_7" and kw["params"]["q"].startswith("after:")
                return Resp(body={"messages": [{"id": "g2"}], "nextPageToken": "p2"})
            if url.endswith("/messages"):
                return Resp(body={"messages": [{"id": "g1"}]})
            if url.endswith("/messages/g1"):
                return Resp(body={"raw": base64.urlsafe_b64encode(RAW).decode().rstrip("=")})
            raise AssertionError(url)

        with mock.patch.object(ms._Http, "__init__", lambda self_: None), mock.patch.object(ms._Http, "call", call):
            src = ms.make_source(self.env)
            items = src.list(2)
            self.assertEqual(items, [("gmail:g1", "g1"), ("gmail:g2", "g2")])   # oldest first
            self.assertEqual(list(src.fetch(items[:1])), [("gmail:g1", RAW)])

    def test_delegation_missing_explained(self):
        def call(self_, method, url, what, **kw):
            return Resp(401, {"error": "unauthorized_client", "error_description": "Client is unauthorized"})

        with mock.patch.object(ms._Http, "__init__", lambda self_: None), mock.patch.object(ms._Http, "call", call):
            with self.assertRaisesRegex(ms.MailSourceError, "domain-wide delegation"):
                ms.make_source(self.env).list(1)

    def test_bad_key_file(self):
        with self.assertRaisesRegex(ms.MailSourceError, "JSON key file"):
            ms.make_source({**self.env, "GMAIL_SERVICE_ACCOUNT_FILE": str(self.keyfile) + ".missing"})


class ImapAndStateTest(unittest.TestCase):
    def test_imap_settings(self):
        with self.assertRaisesRegex(ms.MailSourceError, "IMAP_PASSWORD"):
            ms.make_source({"MAIL_PROVIDER": "imap", "IMAP_SERVER": "mail.example.org", "IMAP_USER": "u"})
        with self.assertRaisesRegex(ms.MailSourceError, "MAIL_PROVIDER must be"):
            ms.make_source({"MAIL_PROVIDER": "pigeon"})

    def test_imap_key_is_the_servers_not_the_senders(self):
        """Two messages with the SAME Message-ID (a forger copying a coming report's) get different keys: the server's
        UIDVALIDITY:UID, never the Message-ID header (external review, 2026-11-12). The old key is kept as legacy."""
        hdr = b"Message-ID: <same@shadowserver.org>\r\nSubject: x\r\n\r\n"

        class FakeImap:
            def search(self, *a):
                return "OK", [b"1 2"]

            def fetch(self, ids, what):
                assert "UID" in what and "BODY.PEEK" in what
                return "OK", [(b"1 (UID 101 BODY[HEADER.FIELDS (MESSAGE-ID DATE SUBJECT FROM)] {50}", hdr), b")",
                              (b"2 (BODY[HEADER.FIELDS (MESSAGE-ID DATE SUBJECT FROM)] {50} UID 102", hdr), b")"]
        src = ms.ImapSource({"IMAP_SERVER": "mail.example.org", "IMAP_USER": "u", "IMAP_PASSWORD": "p"})
        src.imap, src.uidvalidity = FakeImap(), "7"
        items = src.list(1)
        self.assertEqual(items, [("imap:7:101", b"1"), ("imap:7:102", b"2")])
        self.assertEqual(set(src.legacy.values()), {"imap:<same@shadowserver.org>"})

    def test_folder_names_quoted(self):
        """imaplib sends arguments as they are: a folder name with a space must be quoted or the server refuses it."""
        self.assertEqual(ms.imap_quote("Shadow Reports"), '"Shadow Reports"')
        self.assertEqual(ms.imap_quote("inbox"), '"inbox"')
        self.assertEqual(ms.imap_quote('"Already quoted"'), '"Already quoted"')
        self.assertEqual(ms.imap_quote('a "b" c\\d'), '"a \\"b\\" c\\\\d"')

    def test_state(self):
        with tempfile.TemporaryDirectory() as d:
            st = ms.MailState(Path(d) / "s.sqlite")
            st.mark_messages(["k1"]); st.mark_links([("https://dl.shadowserver.org/x", "a.csv")])
            st.close()
            st = ms.MailState(Path(d) / "s.sqlite")
            self.assertEqual(st.done_messages(), {"k1"})
            self.assertEqual(st.done_links(), {"https://dl.shadowserver.org/x"})
            st.close()

    def test_broken_file_is_fetched_again(self):
        """A file found broken later (corrupt zip, deleted) reopens the message and the link that gave it."""
        with tempfile.TemporaryDirectory() as d:
            st = ms.MailState(Path(d) / "s.sqlite")
            st.mark_messages(["k1", "k2"])
            st.mark_links([("https://dl.shadowserver.org/x", "b.csv")])
            st.mark_files([("a.zip", "k1")])
            self.assertEqual(st.forget_file("a.zip"), 1)
            self.assertEqual(st.done_messages(), {"k2"})                  # k1 is fetched again, k2 stays done
            self.assertEqual(st.forget_file("b.csv"), 1)
            self.assertEqual(st.done_links(), set())                      # the link is downloaded again
            self.assertEqual(st.forget_file("unknown.zip"), 0)
            st.close()


class AttachmentTest(unittest.TestCase):
    """The e-mail stage never marks a message done when one of its attachments could not be saved, and decodes
    attachment names split into several encoded pieces in full."""

    def _msg(self, filename_header):
        raw = ("From: reports@shadowserver.org\r\nSubject: t\r\nMIME-Version: 1.0\r\n"
               "Content-Type: multipart/mixed; boundary=XX\r\n\r\n--XX\r\nContent-Type: text/plain\r\n\r\n"
               "see https://dl.shadowserver.org/tok?k\r\n--XX\r\nContent-Type: application/zip\r\n"
               f"Content-Disposition: attachment; filename=\"{filename_header}\"\r\n"
               "Content-Transfer-Encoding: base64\r\n\r\nUEsFBgAAAAAAAAAAAAAAAAAAAAAAAA==\r\n--XX--\r\n")
        import email
        return email.message_from_string(raw)

    def test_save_failure_is_reported(self):
        import shadowserver_pipeline as sp
        from collections import Counter
        with tempfile.TemporaryDirectory() as d:
            stats, links, names = Counter(), set(), []
            with mock.patch.object(sp, "atomic_write", side_effect=OSError("disk full")):
                failed = sp._handle_message(self._msg("2026-11-07-scan_ntp-123-country-geo.csv.zip"), Path(d), stats, links, "1/1", names)
            self.assertEqual(failed, 1)
            self.assertEqual(stats["attachments_failed"], 1)
            self.assertEqual(names, ["2026-11-07-scan_ntp-123-country-geo.csv.zip"])
            self.assertFalse((Path(d) / names[0]).exists())
            failed = sp._handle_message(self._msg("2026-11-07-scan_ntp-123-country-geo.csv.zip"), Path(d), Counter(), set(), "1/1", [])
            self.assertEqual(failed, 0)
            self.assertTrue((Path(d) / "2026-11-07-scan_ntp-123-country-geo.csv.zip").exists())

    def test_links_only_without_attachment(self):
        """The link of an e-mail that has an attachment is the same report: never downloaded, whether the attachment
        is new or already on disk. An e-mail with no attachment gives its link."""
        import email
        import shadowserver_pipeline as sp
        from collections import Counter
        with tempfile.TemporaryDirectory() as d:
            links = set()
            sp._handle_message(self._msg("a.csv.zip"), Path(d), Counter(), links, "1/1", [])     # new attachment
            sp._handle_message(self._msg("a.csv.zip"), Path(d), Counter(), links, "1/1", [])     # already on disk
            self.assertEqual(links, set())
            only_link = email.message_from_string("From: r@shadowserver.org\r\nSubject: t\r\n\r\n"
                                                  "https://dl.shadowserver.org/tok?k\r\n")
            sp._handle_message(only_link, Path(d), Counter(), links, "1/1", [])
            self.assertEqual(links, {"https://dl.shadowserver.org/tok?k"})

    def test_long_encoded_name_in_full(self):
        import shadowserver_pipeline as sp
        from collections import Counter
        name = "2026-11-07-scan_ntp-13474-gh_tld-rhost.csv.zip"
        enc = " ".join("=?UTF-8?B?" + base64.b64encode(p.encode()).decode() + "?=" for p in (name[:20], name[20:]))
        with tempfile.TemporaryDirectory() as d:
            names = []
            sp._handle_message(self._msg(enc), Path(d), Counter(), set(), "1/1", names)
            self.assertEqual(names, [name])


if __name__ == "__main__":
    unittest.main()
