import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class PortalUiSourceTests(unittest.TestCase):
    def test_page_modules_reduce_typical_initial_js_and_keep_one_navigation_model(self):
        static = ROOT / "portal/app/static"
        templates = ROOT / "portal/app/templates"
        baseline = 45_834
        base_size = (static / "base.js").stat().st_size
        export_size = (static / "user-export.js").stat().st_size
        users_size = (
            base_size + export_size + (static / "users.js").stat().st_size
        )
        settings_size = (
            base_size + export_size + (static / "update.js").stat().st_size
        )
        self.assertLessEqual(users_size, int(baseline * 0.65))
        self.assertLessEqual(settings_size, int(baseline * 0.65))

        base = (templates / "base.html").read_text(encoding="utf-8")
        self.assertIn("filename='base.js'", base)
        self.assertNotIn("filename='app.js'", base)
        self.assertIn("navigation_links(navigation_items, true)", base)
        self.assertIn("navigation_links(navigation_items)", base)
        self.assertIn("command_links(navigation_items)", base)
        self.assertEqual(
            base.count("public_url(item.endpoint)"),
            0,
            "Рендер модели должен оставаться в одном partial.",
        )

        expected = {
            "dashboard.html": "dashboard.js",
            "settings.html": "update.js",
            "root_shell.html": "root-shell.js",
            "logs.html": "logs.js",
            "users.html": "users.js",
            "network.html": "network.js",
            "services.html": "services.js",
        }
        for template_name, asset in expected.items():
            text = (templates / template_name).read_text(encoding="utf-8")
            self.assertIn(f"filename='{asset}'", text)
        for template_name in ("login.html", "user_form.html", "certificates.html"):
            text = (templates / template_name).read_text(encoding="utf-8")
            for asset in ("dashboard.js", "update.js", "root-shell.js", "logs.js"):
                self.assertNotIn(asset, text)

    @staticmethod
    def contrast_ratio(foreground: str, background: str) -> float:
        def luminance(color: str) -> float:
            channels = [int(color[index:index + 2], 16) / 255 for index in (1, 3, 5)]
            linear = [channel / 12.92 if channel <= 0.04045 else ((channel + 0.055) / 1.055) ** 2.4 for channel in channels]
            return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]

        lighter, darker = sorted((luminance(foreground), luminance(background)), reverse=True)
        return (lighter + 0.05) / (darker + 0.05)

    def test_primary_color_pairs_meet_wcag_aa_and_assets_are_local(self):
        css_path = ROOT / "portal/app/static/style.css"
        script_paths = sorted((ROOT / "portal/app/static").glob("*.js"))
        css = css_path.read_text(encoding="utf-8")
        script = "\n".join(path.read_text(encoding="utf-8") for path in script_paths)
        light = css.split('html[data-theme="dark"]', 1)[0]
        dark = re.search(r'html\[data-theme="dark"\]\s*\{(.*?)\n\}', css, re.DOTALL)
        self.assertIsNotNone(dark)
        for palette in (light, dark.group(1)):
            tokens = dict(re.findall(r'(--[\w-]+):\s*(#[0-9a-fA-F]{6})', palette))
            for foreground, background in [
                ("--text", "--surface"), ("--muted", "--surface"),
                ("--accent-contrast", "--accent"), ("--success", "--success-bg"),
                ("--warning", "--warning-bg"), ("--danger", "--danger-bg"),
            ]:
                self.assertGreaterEqual(self.contrast_ratio(tokens[foreground], tokens[background]), 4.5, f"{foreground}/{background}")
        self.assertLessEqual(css_path.stat().st_size, 40_000)
        self.assertLessEqual(max(path.stat().st_size for path in script_paths), 16_000)
        self.assertLessEqual(sum(path.stat().st_size for path in script_paths), 72_000)
        self.assertNotRegex(css, r"@import|url\(\s*['\"]?https?://")
        self.assertNotRegex(script, r"https?://")

    def test_user_detail_explains_client_compatibility_and_separate_wireguard_import(self):
        template = (ROOT / "portal/app/templates/user_detail.html").read_text(encoding="utf-8")
        catalog = (ROOT / "portal/app/service_catalog.py").read_text(encoding="utf-8")
        for marker in [
            "AmneziaWG app", "wg0/51821", "awg0/51820",
            "karing-wireguard-qr", "karing-wireguard-url", "karing-wireguard-config",
            "IP SAN", "HAPP/Karing",
        ]:
            self.assertIn(marker, catalog)
        for marker in [
            "client_file_group(file.kind)", "is_qr_file(file.kind)",
            "guidance_note('wireguard-pair')", "guidance_note('happ-karing')",
        ]:
            self.assertIn(marker, template)
        self.assertNotIn("file.kind in [", template)

    def test_mobile_navigation_and_sensitive_update_have_no_overlay_or_password_retention(self):
        base = (ROOT / "portal/app/templates/base.html").read_text(encoding="utf-8")
        settings = (ROOT / "portal/app/templates/settings.html").read_text(encoding="utf-8")
        css = (ROOT / "portal/app/static/style.css").read_text(encoding="utf-8")
        script = "\n".join(
            (ROOT / f"portal/app/static/{name}").read_text(encoding="utf-8")
            for name in ("base.js", "update.js")
        )
        self.assertIn("data-mobile-menu", base)
        self.assertLess(base.index("data-mobile-menu"), base.index('id="content"'))
        self.assertNotIn(".mobile-menu { position: fixed", css)
        for marker in ["closeMobileMenu", 'event.key !== "Escape"', "pointerdown", "mobileMenu.querySelectorAll(\"a\")"]:
            self.assertIn(marker, script)
        for marker in ["data-update-prepare", "data-update-progress", "data-sensitive-submit", "data-sensitive-submit-status", "project-update-hint"]:
            self.assertIn(marker, settings)
        for marker in ["formdata", "clearPassword", "aria-busy", "data-sensitive-submit-button", "XMLHttpRequest"]:
            self.assertIn(marker, script)

    def test_staged_update_ui_has_progress_ready_start_and_no_js_fallback(self):
        settings = (ROOT / "portal/app/templates/settings.html").read_text(encoding="utf-8")
        script = (ROOT / "portal/app/static/update.js").read_text(encoding="utf-8")
        css = (ROOT / "portal/app/static/style.css").read_text(encoding="utf-8")
        prepare_form = settings.split('data-update-prepare', 1)[1].split("</form>", 1)[0]
        self.assertNotIn("root_password", prepare_form)
        self.assertNotIn("project_update_start", prepare_form)
        for marker in [
            "project_release_check", "project_release_prepare",
            "project_update_prepare", "data-update-submit", "data-update-cancel", "data-update-retry",
            'role="status"', 'aria-live="polite"', 'aria-valuenow="0"', "data-update-progress-bar",
            "project_update_start", "project_update_discard", 'name="prepared_id"',
            'name="root_password"', 'data-confirm="Запустить обновление проекта"',
            "github_settings.repository", "Проверить GitHub", "Скачать и проверить",
            "Обновление вручную с сервера", "sudo ./tools/project-backup.sh",
            "sha256sum &lt;archive&gt;", "sudo ./update.sh &lt;archive&gt;",
            "sudo ./update.sh --bootstrap-only &lt;archive&gt;",
        ]:
            self.assertIn(marker, settings)
        update_script = script
        for marker in [
            '"idle"', '"uploading"', '"verifying"', '"ready"', '"error"', '"aborted"',
            "progressEvent.loaded", "selectedFile.size", "aria-valuenow", "xhr.upload", "updateRequest?.abort()",
            'X-CSRF-Token', 'X-KVN-Archive-Name', 'application/octet-stream', "xhr.send(selectedFile)",
            "window.location.reload()", "textContent",
            '"checking"', '"preparing"', "data-github-progress",
        ]:
            self.assertIn(marker, update_script)
        self.assertNotIn("innerHTML", update_script)
        for marker in [".update-progress", ".update-ready-card", ".update-meta", ".update-actions"]:
            self.assertIn(marker, css)

    def test_visual_tokens_keep_release_constraints(self):
        css = (ROOT / "portal/app/static/style.css").read_text(encoding="utf-8")
        for token in ["--radius-sm", "--radius", "--radius-lg"]:
            match = re.search(rf"{re.escape(token)}:\s*([0-9.]+)rem", css)
            self.assertIsNotNone(match, token)
            self.assertLessEqual(float(match.group(1)), 0.5, token)
        self.assertIn("button, .button { min-height: 2.75rem", css)
        self.assertIn("input, select { width: 100%; min-height: 2.75rem", css)
        self.assertIn(".inline-form input, .inline-form select, .inline-form button { min-height: 2.75rem", css)
        self.assertNotRegex(css, r"font-size:\s*clamp\([^;]*vw")
        self.assertNotRegex(css, r"letter-spacing:\s*-")

    def test_base_template_keeps_navigation_and_session_meta_accessible(self):
        base = (ROOT / "portal/app/templates/base.html").read_text(encoding="utf-8")
        navigation = (ROOT / "portal/app/navigation.py").read_text(encoding="utf-8")
        for marker in [
            "skip-link",
            'nav class="nav-list" aria-label=',
            "session-meta",
            "login_ip",
            "build_id",
            "data-theme-toggle aria-label",
            "data-command-palette",
            "data-command-open",
            "Ctrl K",
        ]:
            self.assertIn(marker, base)
        for endpoint in ("backups_view", "project_info", "root_shell_view", "terminal_view"):
            self.assertIn(f'"endpoint": "{endpoint}"', navigation)
        self.assertIn("filename='icon.svg'", base)
        self.assertTrue((ROOT / "portal/app/static/icon.svg").is_file())

    def test_new_network_and_matrix_copy_supports_both_languages(self):
        network = (ROOT / "portal/app/templates/network.html").read_text(encoding="utf-8")
        users = (ROOT / "portal/app/templates/users.html").read_text(encoding="utf-8")
        settings = (ROOT / "portal/app/templates/settings.html").read_text(encoding="utf-8")
        for russian, english in [
            ("Советник доменов", "Domain advisor"),
            ("Рекомендация", "Recommendation"),
            ("Опасное совпадение с сервером", "Same-server hard warning"),
            ("Пользователь × протокол", "User × protocol"),
            ("SNI уровня сервиса", "Service-level SNI"),
            ("не назначен", "not assigned"),
        ]:
            self.assertIn(russian, network + users)
            self.assertIn(english, network + users)
        self.assertIn('autocomplete="username"', settings)

    def test_settings_has_clear_sections_ip_state_and_mobile_sni_cards(self):
        settings = (ROOT / "portal/app/templates/settings.html").read_text(encoding="utf-8")
        css = (ROOT / "portal/app/static/style.css").read_text(encoding="utf-8")
        for marker in [
            'class="settings-nav"', 'href="#interface"', 'href="#portal-performance"',
            'href="#security"', 'href="#project-update"', 'href="#sni-settings"',
            "IP HTTPS готов", "IP HTTPS ожидает сертификат", "совпадающем IP SAN",
            'class="sni-table"', 'data-label="Действия"',
        ]:
            self.assertIn(marker, settings)
        for marker in [
            ".settings-nav", ".sni-table thead", "content: attr(data-label)",
            "position: static", "flex-wrap: wrap",
        ]:
            self.assertIn(marker, css)

    def test_network_page_has_progressive_topology_and_safe_refresh(self):
        app = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (
                ROOT / "portal/app/__init__.py",
                ROOT / "portal/app/blueprints/views.py",
            )
        )
        base = (ROOT / "portal/app/templates/base.html").read_text(encoding="utf-8")
        navigation = (ROOT / "portal/app/navigation.py").read_text(encoding="utf-8")
        template = (ROOT / "portal/app/templates/network.html").read_text(encoding="utf-8")
        script = (ROOT / "portal/app/static/network.js").read_text(encoding="utf-8")
        for marker in ["network_view", "network_json", "network.topology", "dashboard_snapshot()"]:
            self.assertIn(marker, app)
        self.assertIn("navigation_links(navigation_items", base)
        self.assertIn('"endpoint": "network_view"', navigation)
        for zone in ['data-network-zone="ingress"', 'data-network-zone="routing"', 'data-network-zone="protocols"']:
            self.assertIn(zone, template)
        for marker in ["data-network-filter", "data-protocol-card", "ingress → router/direct → backend", "empty-state", 'role="status"']:
            self.assertIn(marker, template)
        refresh = script.split('const networkPanel = document.querySelector("[data-network]")', 1)[1]
        for marker in ["textContent", 'Accept": "application/json"', 'cache: "no-store"', "document.hidden"]:
            self.assertIn(marker, refresh)
        self.assertNotIn("innerHTML", refresh)

    def test_user_matrix_has_nine_columns_live_filter_and_mobile_scroll(self):
        template = (ROOT / "portal/app/templates/users.html").read_text(encoding="utf-8")
        script = (ROOT / "portal/app/static/users.js").read_text(encoding="utf-8")
        css = (ROOT / "portal/app/static/style.css").read_text(encoding="utf-8")
        for marker in ["view='matrix'", "data-user-matrix", "data-protocol-column", "data-access-state", "effective_sni", "service-level SNI", "not applicable", "data-users-empty", "data-users-no-match", "data-users-client-no-match"]:
            self.assertIn(marker, template)
        for marker in ["data-user-live-filter", "data-user-item", "filterUsers", "data-users-client-no-match"]:
            self.assertIn(marker, script if marker == "filterUsers" else template + script)
        for marker in [".user-matrix-scroll", "overflow: auto", "position: sticky", "left: 0", "top: 0", "min-width: 88rem"]:
            self.assertIn(marker, css)

    def test_user_export_dialog_and_settings_are_secret_free_and_accessible(self):
        users = (ROOT / "portal/app/templates/users.html").read_text(
            encoding="utf-8",
        )
        detail = (ROOT / "portal/app/templates/user_detail.html").read_text(
            encoding="utf-8",
        )
        dialog = (ROOT / "portal/app/templates/_user_export.html").read_text(
            encoding="utf-8",
        )
        settings = (ROOT / "portal/app/templates/settings.html").read_text(
            encoding="utf-8",
        )
        script = (ROOT / "portal/app/static/user-export.js").read_text(
            encoding="utf-8",
        )
        for template in (users, detail):
            self.assertIn("export_trigger", template)
            self.assertIn("export_dialog", template)
            self.assertIn("user-export.js", template)
        for marker in [
            "data-user-export-dialog", "data-user-export-trigger",
            "ZIP для Telegram", "data-export-copy", "data-export-mode",
            'role="status"', "method=\"dialog\"", "Проверить сертификат",
        ]:
            self.assertIn(marker, users + detail + dialog)
        for marker in [
            'id="client-export"', "data-client-export-form",
            "include_alternate", "client_export.revision",
            "IP SAN сертификата", "не выдаются по IP",
            "data-client-export-preview", "data-client-export-error",
        ]:
            self.assertIn(marker, settings)
        for marker in [
            'cache: "no-store"', 'credentials: "same-origin"',
            "navigator.clipboard", "textContent", "showModal",
            'dialog.addEventListener("close"', "setCustomValidity",
            "reportValidity", "isPublicIpv4",
        ]:
            self.assertIn(marker, script)
        self.assertNotIn("innerHTML", script)
        for forbidden in [
            "archive_base64", "text_base64", "private_key",
            "sub_token", "root_password",
        ]:
            self.assertNotIn(forbidden, dialog + script)

    def test_primary_templates_have_visible_empty_or_status_states(self):
        for relative in [
            "portal/app/templates/dashboard.html",
            "portal/app/templates/services.html",
            "portal/app/templates/logs.html",
            "portal/app/templates/settings.html",
            "portal/app/templates/terminal.html",
            "portal/app/templates/root_shell_panel.html",
            "portal/app/templates/backups.html",
            "portal/app/templates/backup_result.html",
        ]:
            text = (ROOT / relative).read_text(encoding="utf-8")
            self.assertRegex(text, r"(empty-state|role=\"status\"|role=\"alert\")", relative)

    def test_backup_ui_routes_mount_and_download_are_bounded(self):
        app_source = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (
                ROOT / "portal/app/__init__.py",
                ROOT / "portal/app/blueprints/views.py",
            )
        )
        backups_template = (ROOT / "portal/app/templates/backups.html").read_text(encoding="utf-8")
        result_template = (ROOT / "portal/app/templates/backup_result.html").read_text(encoding="utf-8")
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")

        for marker in [
            "BACKUP_FILENAME_RE = re.compile",
            'BACKUP_DIR=Path(os.environ.get("KVN_BACKUP_DIR", "/backup"))',
            'call_agent("backup.list", {})',
            'call_agent("project.backup", {})',
            "def backup_download(filename: str):",
            "path.parent != backup_dir",
            "path.is_symlink()",
            "send_file(",
        ]:
            self.assertIn(marker, app_source)
        self.assertIn(r"kvn-vpn-backup-[A-Za-z0-9_.-]+\.tar", app_source)
        self.assertIn("- /backup:/backup:ro", compose)
        self.assertNotIn("docker.sock", compose)
        for marker in ["data-confirm=\"Создать бэкап проекта\"", "backup_download", "notice-warning"]:
            self.assertIn(marker, backups_template)
        for marker in ["journal_command", "tools/restore-backup.sh", "role=\"status\""]:
            self.assertIn(marker, result_template)

    def test_project_reference_has_copyable_secret_free_commands(self):
        template = (ROOT / "portal/app/templates/project_info.html").read_text(encoding="utf-8")
        for marker in [
            "Архитектура", "Порты и пути", "Команды", "cmd-setup",
            "cmd-prod-check", "cmd-bootstrap", "cmd-github",
            "ZIP для Telegram", "Прямой отправки через Telegram API нет",
            "IP-экспорт меняет endpoint",
        ]:
            self.assertIn(marker, template)
        command_ids = re.findall(r"command_block\('([^']+)'", template)
        self.assertGreaterEqual(len(command_ids), 7)
        self.assertEqual(len(command_ids), len(set(command_ids)))
        self.assertIn('<code id="{{ id }}">', template)
        self.assertIn('data-copy-target="{{ id }}"', template)
        for forbidden in ["agent.secret", "password_hash", "PRIVATE KEY", "BEGIN PRIVATE KEY", "198.51.100"]:
            self.assertNotIn(forbidden, template)

    def test_logs_refresh_uses_json_endpoint_not_html_parse(self):
        template = (ROOT / "portal/app/templates/logs.html").read_text(encoding="utf-8")
        script = (ROOT / "portal/app/static/logs.js").read_text(encoding="utf-8")
        for marker in ["data-logs-endpoint", "logs_json", "data-log-updated", "data-log-command"]:
            self.assertIn(marker, template)
        for marker in ['Accept": "application/json"', 'cache: "no-store"', "window.setTimeout(refreshLogs, 20000)"]:
            self.assertIn(marker, script)
        self.assertNotIn("DOMParser", script)
        self.assertNotIn('Accept": "text/html"', script)

    def test_services_page_has_client_filters_and_compact_actions(self):
        template = (ROOT / "portal/app/templates/services.html").read_text(encoding="utf-8")
        script = (ROOT / "portal/app/static/services.js").read_text(encoding="utf-8")
        css = (ROOT / "portal/app/static/style.css").read_text(encoding="utf-8")

        for marker in [
            "data-service-filter",
            "data-service-status",
            "data-service-kind",
            "data-service-card",
            "data-service-empty",
            "service-card-meta",
        ]:
            self.assertIn(marker, template)
        for marker in ["filterServices", "data-service-card", "shownServices"]:
            self.assertIn(marker, script)
        for marker in ["data-inline-log-toggle", "data-inline-log-panel", "data-inline-log-endpoint", "data-inline-log-refresh", "Полный журнал"]:
            self.assertIn(marker, template)
        for marker in ["toggle?.addEventListener", "refresh?.addEventListener", "textContent", 'Accept": "application/json"', "aria-expanded"]:
            self.assertIn(marker, (ROOT / "portal/app/static/service-logs.js").read_text(encoding="utf-8"))
        self.assertIn(".action-group { display:flex", css)
        self.assertIn(".service-actions { display:grid;grid-template-columns:repeat(2, minmax(0, 1fr));}", css)
        self.assertIn("#interface form > button", css)
        self.assertIn("justify-self:start", css)

    def test_dashboard_charts_show_absolute_values(self):
        template = (ROOT / "portal/app/templates/dashboard.html").read_text(encoding="utf-8")
        script = (ROOT / "portal/app/static/dashboard.js").read_text(encoding="utf-8")
        css = (ROOT / "portal/app/static/style.css").read_text(encoding="utf-8")

        for marker in ["data-extra-current", "memory_used", "disk_used", "load1", "chart-kpis"]:
            self.assertIn(marker, template)
        for marker in ['unit === "Б"', "data-chart-now", "extraText"]:
            self.assertIn(marker, script)
        self.assertIn(".chart-kpis", css)

    def test_terminal_page_has_allowlist_and_authenticated_root_shell(self):
        app_source = (ROOT / "portal/app/__init__.py").read_text(encoding="utf-8")
        agent_source = (ROOT / "portal/agent.py").read_text(encoding="utf-8")
        protocol = (ROOT / "portal/agent_protocol.py").read_text(encoding="utf-8")
        template = (ROOT / "portal/app/templates/terminal.html").read_text(encoding="utf-8")
        shell_template = (ROOT / "portal/app/templates/root_shell.html").read_text(encoding="utf-8")
        shell_panel = (ROOT / "portal/app/templates/root_shell_panel.html").read_text(encoding="utf-8")
        script = (ROOT / "portal/app/static/root-shell.js").read_text(encoding="utf-8")

        for marker in ["maintenance.commands", "maintenance.run", "MaintenanceCommand", "_maintenance_run"]:
            self.assertIn(marker, agent_source + protocol + app_source)
        for marker in ["shell.open", "shell.read", "shell.write", "shell.close", "_verify_root_password", "RootShellSession"]:
            self.assertIn(marker, agent_source + protocol + app_source)
        for marker in ["terminal_intro", 'name="command"', "data-confirm", "terminal-output", "root_shell_view"]:
            self.assertIn(marker, template)
        for marker in ["data-root-shell", 'name="root_password"', "data-shell-terminal", "data-shell-xterm"]:
            self.assertIn(marker, shell_panel)
        for marker in ["vendor/xterm/xterm.js", "vendor/xterm/addon-fit.js", "shell-wide", "shell-console"]:
            self.assertIn(marker, shell_template)
        for marker in ["window.Terminal", "window.FitAddon", "xterm.onData", "xterm.onResize", "queueShellData", "shellTerminalMissing", "shellReconnecting"]:
            self.assertIn(marker, script)
        for relative in ["portal/app/static/vendor/xterm/xterm.js", "portal/app/static/vendor/xterm/xterm.css", "portal/app/static/vendor/xterm/addon-fit.js"]:
            self.assertTrue((ROOT / relative).is_file(), relative)
        for forbidden in ['name="argv"', 'name="shell"', "subprocess", "docker.sock", "data-shell-input-form", "data-shell-capture"]:
            self.assertNotIn(forbidden, template + shell_panel)
        self.assertIn('"maintenance.run"', protocol)
        self.assertIn('"shell.open"', protocol)


if __name__ == "__main__":
    unittest.main()
