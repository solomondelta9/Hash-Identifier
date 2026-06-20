# Hash Identifier
# Identifies a hash string and reports which algorithm could have generated it.
# Computes a string or file and outputs the digest for every supported algorithm

import sys
import hashlib
import argparse
import re

SUPPORTED = [
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sha3_224",
    "sha3_256",
    "sha3_384",
    "sha3_512",
]

LENGTH_MAP ={
    32:  ["md5"],
    40:  ["sha1"],
    56:  ["sha224", "sha3_224"],
    64:  ["sha256", "sha3_256"],
    96:  ["sha384", "sha3_384"],
    128: ["sha512", "sha3_512"],
}

def identify(hash_string):
    """Return a list of algorithms whose digest length matches input string."""
    
    candidate = hash_string.strip()
    
    if not re.fullmatch(r"[0-9a-fA-F]+", candidate):
        return None, candidate
    
    length = len(candidate)
    matches = LENGTH_MAP.get(length, [])
    return matches, candidate

def compute_string(text):
    """Compute every supported digest for a text string and return them in a dict."""
    
    results = {}
    
    data = text.encode("utf-8")
    for name in SUPPORTED:
        h = hashlib.new(name)
        h.update(data)
        results[name] = h.hexdigest()
    return results

def compute_file(path):
    """"Compute every supported digest for a file's contents and return them in a dict."""
    
    hashers = {name: hashlib.new(name) for name in SUPPORTED}
    
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            for h in hashers.values():
                h.update(chunk)
                
    return {name: h.hexdigest() for name, h in hashers.items()}

def print_digests(results):
    """Print algorithms names and digests lined up in a column."""
    
    width = max(len(name) for name in results)
    for name in SUPPORTED:
        print(f"{name.rjust(width)} : {results[name]}")
        
def main():
    parser = argparse.ArgumentParser(
        description="Identify an unknown hash or compute digests from input."
    )
    subparsers = parser.add_subparsers(dest="mode", required=True)
    
    # identify mode
    id_parser = subparsers.add_parser(
        "identify", help="Guess the algorithm(s) for a given hash string."
    )
    id_parser.add_argument("hash", help="The hash string to identify.")
    
    # compute mode
    comp_parser = subparsers.add_parser(
        "compute", help="compute all digests from a string or file."
    )
    group = comp_parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-s", "--string", help="Text string to hash.")
    group.add_argument("-f", "--file", help="Path to a file to hash.")
    
    args = parser.parse_args()
    
    if args.mode == "identify":
        matches, candidate = identify(args.hash)
        
        if matches is None:
            print(f"'{candidate}' is not a valid hex hash (contains non-hex characters).")
            return
        
        if not matches:
            print(f"No supported algorithms produces a {len(candidate)}-character hex digest.")
            return
        
        print(f"Input length: {len(candidate)} hex characters")
        print("Possible algorithms(s):")
        for name in matches:
            print(f"  - {name}")
            
        # If SHA-2 and SHA-3 share this length reminder that the length can't tell them apart
        if len(matches) > 1:
            print("\nNote: these share the same digest size. Length can't distinguished")
            print("SHA-2 from SHA-3. Recompute from the original input to confirm.")
            
    elif args.mode == "compute":
        if args.string is not None:
            results = compute_string(args.string)
        else:
            try:
                results = compute_file(args.file)
            except FileNotFoundError:
                print(f"File not found: {args.file}")
                return
            except PermissionError:
                print(f"Permission denied: {args.file}")
                return
            
        print_digests(results)
        
if __name__ == "__main__":
    main()























  


  
