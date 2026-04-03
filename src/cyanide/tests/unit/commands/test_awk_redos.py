import re
import time


def test_awk_regex_redos_safety():
    pattern = re.compile(r"\{print\s+([^}\s][^}]*)\}")

    bad_input = "{print " + " " * 10000

    start_time = time.time()
    match = pattern.search(bad_input)
    end_time = time.time()

    duration = end_time - start_time
    print(f"Regex matching took: {duration:.6f}s")

    assert duration < 0.1
    assert match is None


def test_awk_regex_functionality():
    pattern = re.compile(r"\{print\s+([^}\s][^}]*)\}")

    m1 = pattern.search("{print $1}")
    assert m1 is not None and m1.group(1) == "$1"

    m2 = pattern.search("{print $1, $2}")
    assert m2 is not None and m2.group(1) == "$1, $2"

    m3 = pattern.search("{print \t $1}")
    assert m3 is not None and m3.group(1) == "$1"
