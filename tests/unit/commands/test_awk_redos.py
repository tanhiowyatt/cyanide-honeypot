import re
import time


def test_awk_regex_redos_safety():
    # Vulnerable regex: r"\{print\s+(.*)\}"
    # Fixed regex: r"\{print\s+([^}\s][^}]*)\}"
    pattern = re.compile(r"\{print\s+([^}\s][^}]*)\}")

    # Large non-matching string that would trigger backtracking in greedy patterns
    # {print followed by many spaces and NO closing brace
    bad_input = "{print " + " " * 10000

    start_time = time.time()
    match = pattern.search(bad_input)
    end_time = time.time()

    duration = end_time - start_time
    print(f"Regex matching took: {duration:.6f}s")

    # Should be extremely fast (<< 0.1s)
    assert duration < 0.1
    assert match is None


def test_awk_regex_functionality():
    pattern = re.compile(r"\{print\s+([^}\s][^}]*)\}")

    # Simple match
    assert pattern.search("{print $1}").group(1) == "$1"

    # Multiple fields
    assert pattern.search("{print $1, $2}").group(1) == "$1, $2"

    # Spaces and tabs
    assert pattern.search("{print \t $1}").group(1) == "$1"
