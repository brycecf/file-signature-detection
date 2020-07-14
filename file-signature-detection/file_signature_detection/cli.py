from binascii import hexlify
import click
from file_signature_detection.lookup_tries import SignatureLookupTrie
from os import path


@click.command()
@click.argument("path_to_target_file", type=click.Path(exists=True))
def cli(path_to_target_file):
    click.secho("Constructing file signatures lookup table...", fg="yellow")
    lookup_path = path.join(path.dirname(__file__), "data", "file_signatures.txt")
    lookup_trie = SignatureLookupTrie()
    lookup_trie.load_signatures_from_csv(lookup_path)
    click.secho("Contructed file signatures lookup table.", fg="green")

    click.secho(f"Reading {path_to_target_file} ...", fg="yellow")
    with open(path_to_target_file, "rb") as target_file:
        file_hex = hexlify(target_file.read()).decode("ascii")
    click.secho(f"Read {path_to_target_file} .", fg="green")

    click.secho(f"Finding signature matches...\n", fg="yellow")
    contenders = find_matches(lookup_trie, file_hex)
    display_results(contenders)


def display_results(results):
    click.secho(":" * 27, fg="green")
    click.secho(":" * 27, fg="green")
    click.secho("::::Possible File Types::::", fg="green")
    click.secho(":" * 27, fg="green")
    click.secho(":" * 27, fg="green")

    if len(results) == 0:
        click.secho("No candidates found. Try Googling this file's header.", fg="red")
    else:
        for i, result in enumerate(results, start=1):
            click.secho(f"\n::::::Candidate #{i}::::::", fg="green")
            for key, value in result.items():
                click.secho(f"{key}: {value}", fg="green")


def find_matches(lookup_trie, file_hex):
    prefix_matches = lookup_trie.lookup(file_hex[:2])
    contenders = []
    max_header = 0

    for match in prefix_matches:
        for signature in match:
            s_header = signature["Header"]
            s_trailer = signature["Trailer"]
            f_hex_rel_header = file_hex[: len(s_header)]
            if f_hex_rel_header == s_header:
                if s_trailer is not None:
                    f_hex_rel_header = file_hex[-len(s_trailer) :]
                    if s_trailer == f_hex_rel_header:
                        contenders.append(signature)
                else:
                    contenders.append(signature)

                if len(s_header) > max_header:
                    max_header = len(s_header)

    return [match for match in contenders if len(match["Header"]) == max_header]
