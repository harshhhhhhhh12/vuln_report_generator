import unittest
from unittest.mock import patch
import subprocess
from scanner import _run, check_open_ports

class TestScanner(unittest.TestCase):
    @patch('scanner.subprocess.run')
    def test_run_success(self, mock_run):
        # Mock successful subprocess execution
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "mocked stdout"
        mock_run.return_value.stderr = ""
        
        rc, out, err = _run("echo 'mocked stdout'")
        
        self.assertEqual(rc, 0)
        self.assertEqual(out, "mocked stdout")
        self.assertEqual(err, "")
        mock_run.assert_called_once()
        # Verify timeout is passed to subprocess.run
        _, kwargs = mock_run.call_args
        self.assertIn('timeout', kwargs)
        self.assertEqual(kwargs['timeout'], 20)

    @patch('scanner.subprocess.run')
    def test_run_timeout(self, mock_run):
        # Mock TimeoutExpired exception
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="mock_cmd", timeout=20)
        
        rc, out, err = _run("sleep 30", timeout=1)
        
        self.assertEqual(rc, -1)
        self.assertEqual(out, "")
        self.assertEqual(err, "Command timed out")

    @patch('scanner.subprocess.run')
    def test_run_exception(self, mock_run):
        # Mock generic Exception
        mock_run.side_effect = Exception("Generic error")
        
        rc, out, err = _run("invalid_command")
        
        self.assertEqual(rc, -1)
        self.assertEqual(out, "")
        self.assertEqual(err, "Generic error")

    @patch('scanner._run')
    def test_check_open_ports_critical(self, mock_run):
        # Mock _run to return a known dangerous port (23 - Telnet)
        mock_run.return_value = (0, "tcp 0 0 0.0.0.0:23 0.0.0.0:* LISTEN", "")
        
        findings = check_open_ports()
        
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "CRITICAL")
        self.assertIn("Telnet", findings[0].title)

if __name__ == '__main__':
    unittest.main()
