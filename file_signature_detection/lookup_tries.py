import csv
import pygtrie as trie


class SignatureLookupTrie:
    def __init__(self):
        self.trie = trie.CharTrie()

    def load_signatures_from_csv(self, path_to_csv):
        def process_row(row):
            header = "".join(row["Header"].lower().split())
            trailer = row["Trailer"]

            if trailer == "(null)" or trailer is None:
                trailer = None
            else:
                trailer = "".join(trailer.lower().split())

            potential_new_sig = {
                "Description": row["Description"],
                "Extension": row["Extension"],
                "Header": header,
                "Trailer": trailer,
            }

            if header not in self.trie:
                self.trie[header] = [potential_new_sig]
            else:
                self.trie[header].append(potential_new_sig)

        with open(path_to_csv, "r") as sig_file:
            sig_reader = csv.DictReader(sig_file)
            for row in sig_reader:
                process_row(row)

    def lookup(self, header_prefix):
        return list(self.trie[header_prefix:])
