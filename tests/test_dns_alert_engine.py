import unittest

from dns_alert_engine import classify_change, record_sets


class DNSAlertEngineTests(unittest.TestCase):

    def test_nameserver_change_is_high(self):
        result = classify_change({
            "field": "dns.NS",
            "previous": '["ns1.old.example"]',
            "current": '["ns1.new.example"]',
        })
        self.assertEqual(result["severity"], "HIGH")

    def test_mx_change_is_medium(self):
        result = classify_change({
            "field": "dns.MX",
            "previous": '["10 mail.old.example"]',
            "current": '["10 mail.new.example"]',
        })
        self.assertEqual(result["severity"], "MEDIUM")

    def test_new_ip_is_low(self):
        result = classify_change({
            "field": "dns.A",
            "previous": '["192.0.2.10"]',
            "current": '["192.0.2.10", "192.0.2.20"]',
        })
        self.assertEqual(result["severity"], "LOW")

    def test_removed_ip_is_medium(self):
        result = classify_change({
            "field": "dns.A",
            "previous": '["192.0.2.10", "192.0.2.20"]',
            "current": '["192.0.2.10"]',
        })
        self.assertEqual(result["severity"], "MEDIUM")

    def test_replaced_ip_is_medium(self):
        result = classify_change({
            "field": "dns.A",
            "previous": '["192.0.2.10"]',
            "current": '["192.0.2.20"]',
        })
        self.assertEqual(result["severity"], "MEDIUM")

    def test_tls_fingerprint_change_is_high(self):
        result = classify_change({
            "field": "tls.sha256_fingerprint",
            "previous": "OLD_FINGERPRINT",
            "current": "NEW_FINGERPRINT",
        })
        self.assertEqual(result["severity"], "HIGH")

    def test_record_addition_and_removal(self):
        added, removed = record_sets({
            "previous": '["192.0.2.10"]',
            "current": '["192.0.2.20"]',
        })
        self.assertEqual(added, ["192.0.2.20"])
        self.assertEqual(removed, ["192.0.2.10"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
