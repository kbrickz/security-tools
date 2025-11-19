#!/usr/bin/env python3
"""
Comprehensive test suite for Security Log Parser

Copyright (c) 2025 Kristen Brickner
Licensed under the MIT License. See LICENSE file for details.

Tests cover:
- Unit tests for individual functions
- Integration tests for complete workflows  
- Error handling and edge cases
- Real-world scenarios

Run with: python3 test_log_parser.py
Or: python3 -m unittest test_log_parser
Or: python3 -m unittest test_log_parser -v (verbose)
"""

import unittest
import os
import sys
import json
import csv
import tempfile
from io import StringIO
import shutil
from unittest import mock

# Import the module we're testing
import log_parser


class TestParseSyslog(unittest.TestCase):
    """Test the parse_syslog function with various inputs"""
    
    def test_valid_syslog_line(self):
        """Test parsing a valid syslog line"""
        line = "Oct 29 14:23:01 webserver sshd[12345]: Failed password for admin"
        result = log_parser.parse_syslog(line)
        
        self.assertIsNotNone(result)
        self.assertEqual(result.timestamp, 'Oct 29 14:23:01')
        self.assertEqual(result.hostname, 'webserver')
        self.assertEqual(result.process, 'sshd')
        self.assertEqual(result.pid, '12345')
        self.assertEqual(result.message, 'Failed password for admin')
    
    def test_valid_syslog_with_special_chars(self):
        """Test parsing syslog line with special characters in message"""
        line = 'Nov 10 10:23:45 server1 app[5678]: User said "Hello, world!"'
        result = log_parser.parse_syslog(line)
        
        self.assertIsNotNone(result)
        self.assertIn('"Hello, world!"', result.message)
    
    def test_invalid_syslog_line(self):
        """Test that malformed lines return None"""
        line = "This is not a valid syslog line at all"
        result = log_parser.parse_syslog(line)
        
        self.assertIsNone(result)
    
    def test_incomplete_syslog_line(self):
        """Test incomplete syslog format"""
        line = "Oct 30 incomplete timestamp format"
        result = log_parser.parse_syslog(line)
        
        self.assertIsNone(result)
    
    def test_empty_line(self):
        """Test that empty string returns None"""
        line = ""
        result = log_parser.parse_syslog(line)
        
        self.assertIsNone(result)


class TestReadFile(unittest.TestCase):
    """Test the read_file function"""
    
    def test_read_valid_file(self):
        """Test reading a valid log file"""
        lines = list(log_parser.read_file('sample.log'))
        
        self.assertIsInstance(lines, list)
        self.assertEqual(len(lines), 8)
        self.assertTrue(all(isinstance(line, log_parser.LogLine) for line in lines))
        self.assertTrue(all(isinstance(line.text, str) for line in lines))
    
    def test_read_empty_file(self):
        """Test reading an empty file"""
        lines = list(log_parser.read_file('empty.log'))
        
        self.assertIsInstance(lines, list)
        self.assertTrue(all(isinstance(line, log_parser.LogLine) for line in lines))
    
    def test_read_single_line_file(self):
        """Test reading a file with single entry"""
        lines = list(log_parser.read_file('test_single.log'))
        
        self.assertIsInstance(lines, list)
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0].number, 1)
    
    def test_read_nonexistent_file(self):
        """Test that reading nonexistent file raises FileNotFoundError"""
        with self.assertRaises(FileNotFoundError):
            list(log_parser.read_file('this_file_does_not_exist.log'))
    
    def test_read_file_with_special_chars(self):
        """Test reading file with special characters"""
        lines = list(log_parser.read_file('test_special_chars.log'))
        
        self.assertIsInstance(lines, list)
        self.assertEqual(len(lines), 4)
        self.assertTrue(all(isinstance(line.decoding_issue, bool) for line in lines))


class TestValidateThresholds(unittest.TestCase):
    """Test the validate_thresholds function"""
    
    def test_valid_single_threshold(self):
        """Test validating a single valid threshold"""
        thresholds = log_parser.validate_thresholds(['failed_logins=10'])
        
        self.assertIsInstance(thresholds, dict)
        self.assertEqual(thresholds['failed_logins'], 10)
    
    def test_valid_multiple_thresholds(self):
        """Test validating multiple thresholds"""
        thresholds = log_parser.validate_thresholds([
            'failed_logins=5',
            'host_activity=20',
            'process_activity=15'
        ])
        
        self.assertEqual(thresholds['failed_logins'], 5)
        self.assertEqual(thresholds['host_activity'], 20)
        self.assertEqual(thresholds['process_activity'], 15)
    
    def test_none_thresholds(self):
        """Test that None input returns None"""
        thresholds = log_parser.validate_thresholds(None)
        self.assertIsNone(thresholds)
    
    def test_empty_list_thresholds(self):
        """Test that empty list returns None"""
        thresholds = log_parser.validate_thresholds([])
        self.assertIsNone(thresholds)
    
    def test_invalid_format_no_equals(self):
        """Test that threshold without '=' raises error"""
        with self.assertRaises(SystemExit):
            log_parser.validate_thresholds(['failed_logins'])
    
    def test_invalid_format_multiple_equals(self):
        """Test that threshold with multiple '=' raises error"""
        with self.assertRaises(SystemExit):
            log_parser.validate_thresholds(['failed_logins=10=20'])
    
    def test_invalid_key(self):
        """Test that unknown threshold key raises error"""
        with self.assertRaises(SystemExit):
            log_parser.validate_thresholds(['unknown_key=10'])
    
    def test_invalid_value_not_integer(self):
        """Test that non-integer value raises error"""
        with self.assertRaises(SystemExit):
            log_parser.validate_thresholds(['failed_logins=abc'])
    
    def test_invalid_value_negative(self):
        """Test that negative value raises error"""
        with self.assertRaises(SystemExit):
            log_parser.validate_thresholds(['failed_logins=-5'])
    
    def test_invalid_value_zero(self):
        """Test that zero value raises error"""
        with self.assertRaises(SystemExit):
            log_parser.validate_thresholds(['failed_logins=0'])


class TestDetectAnomalies(unittest.TestCase):
    """Test the detect_anomalies function"""
    
    def setUp(self):
        """Set up test data before each test"""
        # Parse sample.log for test data
        lines = log_parser.read_file('sample.log')
        self.sample_entries = []
        for record in lines:
            if record.text:
                parsed = log_parser.parse_syslog(record.text)
                if parsed:
                    self.sample_entries.append(parsed)
    
    def test_no_anomalies_with_normal_data(self):
        """Test that normal log data produces no anomalies"""
        anomalies = log_parser.detect_anomalies(self.sample_entries)
        
        self.assertEqual(anomalies['summary']['total_anomalies'], 0)
        self.assertFalse(anomalies['failed_logins']['is_anomaly'])
        self.assertEqual(len(anomalies['high_activity_hosts']), 0)
        self.assertEqual(len(anomalies['process_anomalies']), 0)
    
    def test_failed_login_anomaly_detection(self):
        """Test detection of failed login anomaly"""
        # Parse brute_force.log which has 8 failed logins
        lines = log_parser.read_file('brute_force.log')
        entries = []
        for record in lines:
            if record.text:
                parsed = log_parser.parse_syslog(record.text)
                if parsed:
                    entries.append(parsed)
        
        anomalies = log_parser.detect_anomalies(entries)
        
        # Should detect failed login anomaly (8 > default threshold of 5)
        self.assertTrue(anomalies['failed_logins']['is_anomaly'])
        self.assertEqual(anomalies['failed_logins']['count'], 8)
        self.assertGreaterEqual(anomalies['summary']['total_anomalies'], 1)
    
    def test_custom_thresholds(self):
        """Test anomaly detection with custom thresholds"""
        # Use very low threshold to force anomaly
        custom_thresholds = {'failed_logins': 1, 'host_activity': 5, 'process_activity': 2}
        
        anomalies = log_parser.detect_anomalies(self.sample_entries, custom_thresholds)
        
        # sample.log has 3 failed logins, should trigger with threshold=1
        self.assertTrue(anomalies['failed_logins']['is_anomaly'])
        self.assertEqual(anomalies['failed_logins']['count'], 3)
    
    def test_threshold_boundary(self):
        """Test that count equal to threshold does NOT trigger anomaly"""
        # sample.log has exactly 3 failed logins
        # Set threshold to 3 - should NOT trigger (needs to exceed)
        custom_thresholds = {'failed_logins': 3, 'host_activity': 20, 'process_activity': 15}
        
        anomalies = log_parser.detect_anomalies(self.sample_entries, custom_thresholds)
        
        self.assertFalse(anomalies['failed_logins']['is_anomaly'])
    
    def test_empty_entries(self):
        """Test anomaly detection with no entries"""
        anomalies = log_parser.detect_anomalies([])
        
        self.assertEqual(anomalies['summary']['total_anomalies'], 0)
        self.assertEqual(anomalies['failed_logins']['count'], 0)


class TestExportFunctions(unittest.TestCase):
    """Test export functions (JSON, CSV, text)"""
    
    def setUp(self):
        """Set up test data before each test"""
        lines = log_parser.read_file('test_single.log')
        self.test_entry = []
        for record in lines:
            if record.text:
                parsed = log_parser.parse_syslog(record.text)
                if parsed:
                    self.test_entry.append(parsed)
        
        # Create a temporary directory for output files
        self.test_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up temporary directory after each test"""
        shutil.rmtree(self.test_dir)
    
    def test_export_json_to_file(self):
        """Test exporting to JSON file"""
        output_file = os.path.join(self.test_dir, 'test_output.json')
        
        log_parser.export_json(self.test_entry, output_file)
        
        # Verify file was created
        self.assertTrue(os.path.exists(output_file))
        
        # Verify JSON is valid and contains expected data
        with open(output_file, 'r') as f:
            data = json.load(f)
        
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['hostname'], 'server1')
    
    def test_export_json_stdout(self):
        """Test exporting to JSON stdout"""
        # Capture stdout
        captured_output = StringIO()
        sys.stdout = captured_output
        
        log_parser.export_json(self.test_entry, None)
        
        # Restore stdout
        sys.stdout = sys.__stdout__
        
        # Verify JSON output
        output = captured_output.getvalue()
        data = json.loads(output)
        
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 1)
    
    def test_export_csv_to_file(self):
        """Test exporting to CSV file"""
        output_file = os.path.join(self.test_dir, 'test_output.csv')
        
        log_parser.export_csv(self.test_entry, output_file)
        
        # Verify file was created
        self.assertTrue(os.path.exists(output_file))
        
        # Verify CSV is valid
        with open(output_file, 'r') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['hostname'], 'server1')
        self.assertEqual(rows[0]['process'], 'sshd')
    
    def test_export_csv_with_special_chars(self):
        """Test CSV export handles special characters correctly"""
        # Parse file with special characters
        lines = log_parser.read_file('test_special_chars.log')
        entries = []
        for record in lines:
            if record.text:
                parsed = log_parser.parse_syslog(record.text)
                if parsed:
                    entries.append(parsed)
    
        output_file = os.path.join(self.test_dir, 'special_chars.csv')
        log_parser.export_csv(entries, output_file)
    
        # Verify CSV properly escaped special characters
        with open(output_file, 'r') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
    
        # Verify we got all 4 entries
        self.assertEqual(len(rows), 4)
    
        # Test 1: Quotes are properly handled (CSV module handles escaping)
        # When we read back through csv.DictReader, we should get original string
        self.assertEqual(rows[0]['message'], 'User said "Hello, world!"')
    
        # Test 2: Special characters in JSON-like content preserved
        self.assertIn('{"key": "value"', rows[2]['message'])
    
        # Test 3: Multiple special chars in one message
        self.assertIn('<>&', rows[3]['message'])
    
    def test_export_text_output(self):
        """Test text export to stdout"""
        # Capture stdout
        captured_output = StringIO()
        sys.stdout = captured_output
        
        log_parser.export_text(self.test_entry)
        
        # Restore stdout
        sys.stdout = sys.__stdout__
        
        output = captured_output.getvalue()
        
        # Verify text contains expected information
        self.assertIn('Total entries parsed: 1', output)
        self.assertIn('server1', output)
        self.assertIn('sshd', output)


class TestExportAnomaliesFormatting(unittest.TestCase):
    """Test anomaly export formatting"""

    def setUp(self):
        """Prepare sample anomaly data"""
        self.anomalies = {
            'failed_logins': {
                'count': 2,
                'threshold': 1,
                'is_anomaly': True,
                'entries': [{
                    'timestamp': 'Oct 12 12:00:00',
                    'hostname': 'server1',
                    'message': 'Failed password for admin'
                }]
            },
            'high_activity_hosts': {
                'server1': {'count': 25, 'threshold': 20, 'is_anomaly': True}
            },
            'process_anomalies': {},
            'summary': {
                'total_anomalies': 1,
                'anomaly_types_found': ['failed_logins']
            }
        }

    def test_export_anomalies_default_text(self):
        """Ensure human-readable formatter uses ASCII indicators"""
        captured_output = StringIO()
        with mock.patch('sys.stdout', captured_output):
            log_parser.export_anomalies(self.anomalies)

        output = captured_output.getvalue()
        self.assertIn('[WARNING] 1 anomaly type(s) detected', output)
        self.assertIn('[ALERT] FAILED LOGIN ATTEMPTS', output)
        self.assertNotIn('🚨', output)

    def test_export_anomalies_custom_formatter(self):
        """Ensure custom formatter output is respected"""
        captured_output = StringIO()
        formatter = lambda data: json.dumps({'total': data['summary']['total_anomalies']})

        with mock.patch('sys.stdout', captured_output):
            log_parser.export_anomalies(self.anomalies, formatter=formatter)

        self.assertEqual(captured_output.getvalue().strip(), '{"total": 1}')


class TestIntegration(unittest.TestCase):
    """Integration tests for complete workflows"""
    
    def setUp(self):
        """Set up temporary directory for output files"""
        self.test_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up temporary directory"""
        shutil.rmtree(self.test_dir)
    
    def test_parse_sample_log(self):
        """Test parsing sample.log end-to-end"""
        lines = log_parser.read_file('sample.log')
        entries = []
        
        for record in lines:
            if record.text:
                parsed = log_parser.parse_syslog(record.text)
                if parsed:
                    entries.append(parsed)
        
        # Verify we parsed all 8 valid lines
        self.assertEqual(len(entries), 8)
        
        # Verify variety of processes
        processes = {entry.process for entry in entries}
        self.assertIn('sshd', processes)
        self.assertIn('kernel', processes)
        self.assertIn('systemd', processes)
        self.assertIn('sudo', processes)
    
    def test_parse_malformed_log(self):
        """Test parsing file with mix of valid and invalid lines"""
        lines = log_parser.read_file('malformed.log')
        entries = []
        failed = 0
        
        for record in lines:
            if not record.text:
                continue
            parsed = log_parser.parse_syslog(record.text)
            if parsed:
                entries.append(parsed)
            else:
                failed += 1
        
        # Should have some valid and some invalid
        self.assertGreater(len(entries), 0)
        self.assertGreater(failed, 0)
        
        # Specifically, malformed.log has 6 valid, 4 invalid
        self.assertEqual(len(entries), 6)
        self.assertEqual(failed, 4)
    
    def test_full_workflow_with_json_export(self):
        """Test complete workflow: read → parse → export JSON"""
        lines = log_parser.read_file('test_single.log')
        entries = []
        
        for record in lines:
            if record.text:
                parsed = log_parser.parse_syslog(record.text)
                if parsed:
                    entries.append(parsed)
        
        output_file = os.path.join(self.test_dir, 'workflow_output.json')
        log_parser.export_json(entries, output_file)
        
        # Verify end-to-end success
        self.assertTrue(os.path.exists(output_file))
        
        with open(output_file, 'r') as f:
            data = json.load(f)
        
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['hostname'], 'server1')
    
    def test_anomaly_detection_workflow(self):
        """Test complete anomaly detection workflow"""
        lines = log_parser.read_file('brute_force.log')
        entries = []
        
        for record in lines:
            if record.text:
                parsed = log_parser.parse_syslog(record.text)
                if parsed:
                    entries.append(parsed)
        
        # Run anomaly detection
        anomalies = log_parser.detect_anomalies(entries)
        
        # Verify anomaly was detected
        self.assertTrue(anomalies['failed_logins']['is_anomaly'])
        self.assertEqual(anomalies['failed_logins']['count'], 8)
        
        # Verify anomaly entries are correct
        self.assertEqual(len(anomalies['failed_logins']['entries']), 8)


class TestCLIInterface(unittest.TestCase):
    """Test CLI entry point behaviors"""

    def test_main_json_output_writes_file(self):
        """Verify main() handles --format/--output arguments"""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, 'cli_output.json')
            argv = [
                'log_parser.py',
                '--format', 'json',
                '--output', output_path,
                'sample.log'
            ]
            with mock.patch.object(sys, 'argv', argv):
                log_parser.main()

            self.assertTrue(os.path.exists(output_path))
            with open(output_path, 'r') as handle:
                data = json.load(handle)
            self.assertEqual(len(data), 8)
            self.assertEqual(data[0]['process'], 'sshd')

    def test_main_failed_output_report(self):
        """Verify --failed-output captures unparsable lines"""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, 'cli_output.json')
            failed_path = os.path.join(tmpdir, 'failed.json')
            argv = [
                'log_parser.py',
                '--format', 'json',
                '--output', output_path,
                '--failed-output', failed_path,
                'malformed.log'
            ]
            with mock.patch.object(sys, 'argv', argv):
                log_parser.main()

            self.assertTrue(os.path.exists(failed_path))
            with open(failed_path, 'r') as handle:
                failures = json.load(handle)

            self.assertGreater(len(failures), 0)
            self.assertIn('line_number', failures[0])
            self.assertIn('reasons', failures[0])
class TestErrorHandling(unittest.TestCase):
    """Test error conditions and edge cases"""
    
    def test_validate_output_path_nonexistent_directory(self):
        """Test validation catches nonexistent output directory"""
        with self.assertRaises(SystemExit):
            log_parser.validate_output_path('/this/directory/does/not/exist/output.json')
    
    def test_validate_output_path_none(self):
        """Test that None output path is valid (stdout)"""
        # Should not raise exception
        try:
            log_parser.validate_output_path(None)
        except SystemExit:
            self.fail("validate_output_path raised SystemExit unexpectedly")
    
    def test_validate_output_path_current_directory(self):
        """Test validation allows current directory"""
        # Should not raise exception
        try:
            log_parser.validate_output_path('output.json')
        except SystemExit:
            self.fail("validate_output_path raised SystemExit unexpectedly")


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions"""
    
    def test_empty_log_file(self):
        """Test handling of empty log file"""
        lines = log_parser.read_file('empty.log')
        entries = []
        
        for record in lines:
            if not record.text:
                continue
            parsed = log_parser.parse_syslog(record.text)
            if parsed:
                entries.append(parsed)
        
        # Empty file should result in 0 entries
        self.assertEqual(len(entries), 0)
    
    def test_single_entry_file(self):
        """Test handling of file with single entry"""
        lines = log_parser.read_file('test_single.log')
        entries = []
        
        for record in lines:
            if record.text:
                parsed = log_parser.parse_syslog(record.text)
                if parsed:
                    entries.append(parsed)
        
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].hostname, 'server1')
    
    def test_all_malformed_lines(self):
        """Test file where all lines fail to parse"""
        # Create test data with only malformed lines
        test_lines = [
            "This is not valid",
            "Neither is this",
            "Nor this one"
        ]
        
        entries = []
        for line in test_lines:
            parsed = log_parser.parse_syslog(line)
            if parsed:
                entries.append(parsed)
        
        self.assertEqual(len(entries), 0)


# Test runner configuration
if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)
