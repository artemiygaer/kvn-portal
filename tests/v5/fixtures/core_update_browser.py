"""Локальная разметка обновления; настоящие операции не выполняются."""

from unittest.mock import Mock

from flask import redirect, session

from v5.portal.app import create_app


def main():
    updates = Mock()
    updates.status.return_value = {
        'current': '5.0.0',
        'records': [{'version': '5.0.1', 'sha256': 'a' * 64,
                     'ticket': 'b' * 64, 'status': 'ready'}],
    }
    app = create_app({'session_key': 'browser-fixture-only', 'allowed_hosts': ['127.0.0.1:18778']},
                     client=Mock(), core_update_client=updates)
    app.config.update(SESSION_COOKIE_NAME='fixture-session', SESSION_COOKIE_SECURE=False)

    @app.get('/fixture-login')
    def fixture_login():
        session.update(admin=True, csrf='browser-fixture-only')
        return redirect('/maintenance/update')

    app.run(host='127.0.0.1', port=18778, debug=False)


if __name__ == '__main__':
    main()
