"""Защита публичной страницы и сохранение пользовательского HTML."""

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import Mock, patch

from v5.core.agent import _refresh_public_site
from v5.core.site.document import DEFAULT_SITE, SiteStore, _OLD_DEFAULT, validate_html


class NeutralSiteTests(TestCase):
    def test_upgrade_replaces_only_known_default(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            page = root / "index.html"
            page.write_bytes(_OLD_DEFAULT)
            site = SiteStore(root)
            tls = Mock()
            with patch("v5.core.agent.read_gateway_config",
                       return_value=b"return 308 https://$kvn_public_authority$request_uri;"):
                _refresh_public_site(site, tls, root / "nginx.conf")
            tls.submit_prepare.assert_called_once()
            self.assertEqual(page.read_bytes(), DEFAULT_SITE)
            self.assertIn("Служебный узел".encode(), validate_html(DEFAULT_SITE))
            self.assertNotIn(b"KVN", DEFAULT_SITE)
            site.publish(b"<p>Personal page</p>")
            previous = page.read_bytes()
            site.refresh_default()
            self.assertEqual(page.read_bytes(), previous)
