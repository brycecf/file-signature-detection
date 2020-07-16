from file_signature_detection.lookup_tries import SignatureLookupTrie
from os import path
import pygtrie as trie


class TestSignatureLookupTrie:
    def test_constructor(self):
        empty_trie = trie.CharTrie()
        sig_lookup_trie = SignatureLookupTrie()
        assert sig_lookup_trie.trie.values() == empty_trie.values()

    def test_load_signatures_from_csv(self):
        lookup_trie = SignatureLookupTrie()
        csv_path = path.join(path.dirname(__file__), "test_data", "file_signatures.txt")
        lookup_trie.load_signatures_from_csv(csv_path)

        test_header = "d0cf11e0a1b11ae1"
        test_exp_value = 17
        results = lookup_trie.lookup(test_header)
        assert len(results[0]) == test_exp_value

        test_header = "dba52d00"
        test_exp_value = [
            {
                "Description": "Word 2.0 file",
                "Extension": "DOC",
                "Header": "dba52d00",
                "Trailer": None,
            }
        ]
        results = lookup_trie.lookup(test_header)
        assert results[0] == test_exp_value
