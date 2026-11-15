"""Проверки безопасного предпросмотра и замены статического приветствия."""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from v5.core.site.document import DEFAULT_SITE, MAX_HTML_BYTES, SITE_CSP, SiteStore, UnsafeDocument, validate_html


class SiteDocumentTests(unittest.TestCase):
    def test_plain_page_preserves_text_styles_and_safe_links(self):
        source = ("<!DOCTYPE html><html lang='ru'><head><meta charset='UTF-8'>"
                  "<meta name='viewport' content='width=device-width'><style>main > p {color: teal}</style>"
                  "</head><body><main><p>Текст &amp; знак</p><a href='https://example.net/'>Ссылка</a>"
                  "</main></body></html>").encode()
        document = validate_html(source).decode()
        self.assertIn("main > p {color: teal}", document)
        self.assertIn("Текст &amp; знак", document)
        self.assertIn('href="https://example.net/" rel="noopener noreferrer"', document)
        self.assertIn("default-src 'none'", SITE_CSP)
        self.assertIn("sandbox", SITE_CSP)

    def test_rejects_execution_network_and_malformed_html(self):
        bad = (b"<script>alert(1)</script>", b"<a href='java&#x73;cript:alert(1)'>x</a>",
               b"<img src='https://example.net/private'>", b"<img src='data:image/svg+xml;base64,AAA'>",
               b"<div onclick='x()'>x</div>", b"<meta http-equiv='refresh' content='0; URL=//evil'>",
               b"<iframe srcdoc='x'></iframe>", b"<base href='https://example.net/'>", b"<form></form>",
               b"<a href='https://example.net' href='https://other.net'>x</a>",
               b"<style></style><script>x()</script>", b"<p>bad", b"<svg></svg>",
               b"<p>\x00</p>", b"<p>\xff</p>", b"x" * (MAX_HTML_BYTES + 1))
        for payload in bad:
            with self.subTest(payload=payload[:64]), self.assertRaises(UnsafeDocument):
                validate_html(payload)

    def test_rejected_publication_does_not_change_old_file_and_reset_is_atomic(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            store = SiteStore(root)
            current = root / "index.html"
            store.publish(b"<h1>Public</h1>")
            previous = current.read_bytes()
            self.assertEqual(previous, validate_html(b"<h1>Public</h1>"))
            with self.assertRaises(UnsafeDocument):
                store.publish(b"<script>bad()</script>")
            with patch("v5.core.site.document.os.replace", side_effect=OSError("fixture")), self.assertRaises(OSError):
                store.publish(b"<h1>Another page</h1>")
            self.assertEqual(current.read_bytes(), previous)
            self.assertEqual(list(root.iterdir()), [current])
            store.reset()
            self.assertEqual(current.read_bytes(), DEFAULT_SITE)
