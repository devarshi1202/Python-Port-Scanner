import unittest
from unittest.mock import patch

import port_scanner


class TestPortScanner(unittest.TestCase):
    @patch("port_scanner.socket.socket")
    def test_open_port(self, mock_socket):
        instance = mock_socket.return_value
        instance.connect_ex.return_value = 0

        self.assertTrue(port_scanner.scan_port("127.0.0.1", 80))

    @patch("port_scanner.socket.socket")
    def test_closed_port(self, mock_socket):
        instance = mock_socket.return_value
        instance.connect_ex.return_value = 1

        self.assertFalse(port_scanner.scan_port("127.0.0.1", 81))

    def test_invalid_port_range(self):
        with self.assertRaises(ValueError):
            port_scanner.scan_target("127.0.0.1", 0, 10, 0.5)

    def test_reversed_port_range(self):
        with self.assertRaises(ValueError):
            port_scanner.scan_target("127.0.0.1", 100, 10, 0.5)

    def test_invalid_timeout(self):
        with self.assertRaises(ValueError):
            port_scanner.scan_target("127.0.0.1", 1, 10, 0)


if __name__ == "__main__":
    unittest.main()
