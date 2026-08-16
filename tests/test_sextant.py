"""Tests for Sextant — TLS certificate expiry monitor."""

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import sextant


class TestParseEndpoints(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(sextant.parse_endpoints(""), [])
        self.assertEqual(sextant.parse_endpoints(None), [])
        self.assertEqual(sextant.parse_endpoints("  "), [])

    def test_single_host(self):
        self.assertEqual(sextant.parse_endpoints("example.com"), [("example.com", 443)])

    def test_host_with_port(self):
        self.assertEqual(
            sextant.parse_endpoints("example.com:8443"), [("example.com", 8443)]
        )

    def test_multiple_hosts(self):
        result = sextant.parse_endpoints("a.com,b.com:8443,c.org")
        self.assertEqual(
            result, [("a.com", 443), ("b.com", 8443), ("c.org", 443)]
        )

    def test_whitespace_handling(self):
        result = sextant.parse_endpoints(" a.com , b.com ")
        self.assertEqual(result, [("a.com", 443), ("b.com", 443)])

    def test_ipv6(self):
        result = sextant.parse_endpoints("[::1]:8443")
        self.assertEqual(result, [("::1", 8443)])

    def test_ipv6_default_port(self):
        result = sextant.parse_endpoints("[::1]")
        self.assertEqual(result, [("::1", 443)])


class TestShouldAlert(unittest.TestCase):
    def _result(self, days_left=None, error=None):
        return {
            "host": "example.com",
            "port": 443,
            "subject": "example.com",
            "issuer": "Let's Encrypt",
            "not_after": None,
            "days_left": days_left,
            "error": error,
        }

    def test_no_alert_healthy(self):
        do_alert, _, _ = sextant.should_alert(self._result(days_left=90), 30, 7)
        self.assertFalse(do_alert)

    def test_warn_alert(self):
        do_alert, priority, msg = sextant.should_alert(self._result(days_left=15), 30, 7)
        self.assertTrue(do_alert)
        self.assertEqual(priority, "default")
        self.assertIn("15 days", msg)

    def test_critical_alert(self):
        do_alert, priority, msg = sextant.should_alert(self._result(days_left=3), 30, 7)
        self.assertTrue(do_alert)
        self.assertEqual(priority, "high")
        self.assertIn("critical", msg)

    def test_expired_alert(self):
        do_alert, priority, msg = sextant.should_alert(self._result(days_left=-2), 30, 7)
        self.assertTrue(do_alert)
        self.assertEqual(priority, "urgent")
        self.assertIn("EXPIRED", msg)

    def test_connection_error_alert(self):
        do_alert, priority, msg = sextant.should_alert(
            self._result(error="Connection refused"), 30, 7
        )
        self.assertTrue(do_alert)
        self.assertEqual(priority, "urgent")
        self.assertIn("Connection refused", msg)

    def test_exactly_warn_days(self):
        do_alert, priority, _ = sextant.should_alert(self._result(days_left=30), 30, 7)
        self.assertTrue(do_alert)
        self.assertEqual(priority, "default")

    def test_exactly_crit_days(self):
        do_alert, priority, _ = sextant.should_alert(self._result(days_left=7), 30, 7)
        self.assertTrue(do_alert)
        self.assertEqual(priority, "high")

    def test_zero_days(self):
        do_alert, priority, msg = sextant.should_alert(self._result(days_left=0), 30, 7)
        self.assertTrue(do_alert)
        self.assertEqual(priority, "urgent")
        self.assertIn("EXPIRED", msg)

    def test_non_standard_port_in_message(self):
        result = self._result(days_left=5)
        result["port"] = 8443
        _, _, msg = sextant.should_alert(result, 30, 7)
        self.assertIn("8443", msg)

    def test_standard_port_omitted_from_message(self):
        result = self._result(days_left=5)
        _, _, msg = sextant.should_alert(result, 30, 7)
        self.assertNotIn(":443", msg)


class TestCheckCertificate(unittest.TestCase):
    def test_connection_failure(self):
        result = sextant.check_certificate("localhost", 1, timeout=1)
        self.assertIsNotNone(result["error"])
        self.assertIsNone(result["days_left"])

    @patch("sextant.ssl.create_default_context")
    @patch("sextant.socket.create_connection")
    def test_valid_cert(self, mock_conn, mock_ctx):
        future = datetime.now(timezone.utc) + timedelta(days=60)
        not_after = future.strftime("%b %d %H:%M:%S %Y GMT")
        cert = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("organizationName", "Test CA"),),),
            "notAfter": not_after,
        }
        mock_tls = MagicMock()
        mock_tls.getpeercert.return_value = cert
        mock_tls.__enter__ = MagicMock(return_value=mock_tls)
        mock_tls.__exit__ = MagicMock(return_value=False)

        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = mock_sock

        mock_ssl_ctx = MagicMock()
        mock_ssl_ctx.wrap_socket.return_value = mock_tls
        mock_ctx.return_value = mock_ssl_ctx

        result = sextant.check_certificate("example.com", 443, timeout=5)
        self.assertIsNone(result["error"])
        self.assertEqual(result["subject"], "example.com")
        self.assertEqual(result["issuer"], "Test CA")
        self.assertAlmostEqual(result["days_left"], 60, delta=1)


class TestLoadConfig(unittest.TestCase):
    def test_defaults(self):
        with patch.dict(os.environ, {}, clear=True):
            config = sextant.load_config()
            self.assertEqual(config["endpoints"], [])
            self.assertEqual(config["interval"], 3600)
            self.assertEqual(config["timeout"], 10)
            self.assertEqual(config["warn_days"], 30)
            self.assertEqual(config["crit_days"], 7)
            self.assertEqual(config["cooldown"], 86400)

    def test_custom_values(self):
        env = {
            "ENDPOINTS": "a.com,b.com:8443",
            "CHECK_INTERVAL": "1800",
            "TIMEOUT": "5",
            "WARN_DAYS": "14",
            "CRIT_DAYS": "3",
            "ALERT_COOLDOWN": "3600",
            "NTFY_URL": "http://ntfy.example.com",
            "NTFY_TOPIC": "certs",
        }
        with patch.dict(os.environ, env, clear=True):
            config = sextant.load_config()
            self.assertEqual(len(config["endpoints"]), 2)
            self.assertEqual(config["interval"], 1800)
            self.assertEqual(config["warn_days"], 14)
            self.assertEqual(config["ntfy_topic"], "certs")


class TestSendNtfy(unittest.TestCase):
    @patch("sextant.urllib.request.urlopen")
    def test_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = sextant.send_ntfy(
            "http://localhost:8888", "test", "Title", "Message"
        )
        self.assertTrue(result)

    @patch("sextant.urllib.request.urlopen", side_effect=Exception("fail"))
    def test_failure(self, _):
        result = sextant.send_ntfy(
            "http://localhost:8888", "test", "Title", "Message"
        )
        self.assertFalse(result)


class TestRunChecks(unittest.TestCase):
    @patch("sextant.send_ntfy", return_value=True)
    @patch("sextant.check_certificate")
    def test_alert_sent_on_expiring(self, mock_check, mock_ntfy):
        mock_check.return_value = {
            "host": "example.com",
            "port": 443,
            "subject": "example.com",
            "issuer": "Test",
            "not_after": "2026-08-20T00:00:00+00:00",
            "days_left": 3,
            "error": None,
        }
        config = {
            "endpoints": [("example.com", 443)],
            "timeout": 5,
            "warn_days": 30,
            "crit_days": 7,
            "ntfy_url": "http://localhost:8888",
            "ntfy_topic": "test",
            "cooldown": 86400,
        }
        alert_state = {}
        results = sextant.run_checks(config, alert_state)
        self.assertEqual(len(results), 1)
        mock_ntfy.assert_called_once()
        self.assertIn("example.com:443", alert_state)

    @patch("sextant.send_ntfy", return_value=True)
    @patch("sextant.check_certificate")
    def test_cooldown_suppresses_repeat(self, mock_check, mock_ntfy):
        mock_check.return_value = {
            "host": "example.com",
            "port": 443,
            "subject": "example.com",
            "issuer": "Test",
            "not_after": None,
            "days_left": 3,
            "error": None,
        }
        config = {
            "endpoints": [("example.com", 443)],
            "timeout": 5,
            "warn_days": 30,
            "crit_days": 7,
            "ntfy_url": "http://localhost:8888",
            "ntfy_topic": "test",
            "cooldown": 86400,
        }
        import time

        alert_state = {"example.com:443": time.time()}
        sextant.run_checks(config, alert_state)
        mock_ntfy.assert_not_called()

    @patch("sextant.send_ntfy")
    @patch("sextant.check_certificate")
    def test_no_alert_healthy_cert(self, mock_check, mock_ntfy):
        mock_check.return_value = {
            "host": "example.com",
            "port": 443,
            "subject": "example.com",
            "issuer": "Test",
            "not_after": "2026-12-01T00:00:00+00:00",
            "days_left": 90,
            "error": None,
        }
        config = {
            "endpoints": [("example.com", 443)],
            "timeout": 5,
            "warn_days": 30,
            "crit_days": 7,
            "ntfy_url": "http://localhost:8888",
            "ntfy_topic": "test",
            "cooldown": 86400,
        }
        sextant.run_checks(config, {})
        mock_ntfy.assert_not_called()


if __name__ == "__main__":
    unittest.main()
