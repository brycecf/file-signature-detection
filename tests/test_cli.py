from binascii import hexlify
from file_signature_detection.cli import find_matches
from file_signature_detection.lookup_tries import SignatureLookupTrie
from os import path
import pytest


@pytest.fixture()
def lookup_trie():
    lookup_trie = SignatureLookupTrie()
    csv_path = path.join(path.dirname(__file__), "test_data", "file_signatures.txt")
    lookup_trie.load_signatures_from_csv(csv_path)
    return lookup_trie


def test_find_matches(lookup_trie):
    test_target_dir = path.join(
        path.dirname(__file__), "test_data", "test_target_files"
    )

    first_test_val = [
        {
            "Description": "MIDI sound file",
            "Extension": "MID|MIDI",
            "Header": "4d546864",
            "Trailer": None,
        },
        {
            "Description": "Yamaha Piano",
            "Extension": "PCS",
            "Header": "4d546864",
            "Trailer": None,
        },
    ]
    with open(path.join(test_target_dir, "09.midi"), "rb") as target_file:
        file_hex = hexlify(target_file.read()).decode("ascii")
    results = find_matches(lookup_trie, file_hex)
    assert results == first_test_val

    second_test_val = [
        {
            "Description": "GIF file",
            "Extension": "GIF",
            "Header": "47494638",
            "Trailer": "003b",
        }
    ]
    with open(path.join(test_target_dir, "G.gif"), "rb") as target_file:
        file_hex = hexlify(target_file.read()).decode("ascii")
    results = find_matches(lookup_trie, file_hex)
    assert results == second_test_val
