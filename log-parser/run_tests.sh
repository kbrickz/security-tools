#!/bin/bash
echo "Running log parser tests..."
echo ""

echo "Test 1: sample.log"
python3 log_parser.py sample.log | tail -5
echo ""

echo "Test 2: empty.log"
python3 log_parser.py empty.log | tail -3
echo ""

echo "Test 3: malformed.log"
python3 log_parser.py malformed.log | tail -5
echo ""

echo "Test 4: large.log"
python3 log_parser.py large.log | tail -5
echo ""

echo "All tests complete!"
