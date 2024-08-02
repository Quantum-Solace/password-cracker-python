#!/usr/bin/env python3

import hashlib
import re
import itertools
import argparse
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
import os
import string
import functools
from typing import List, Optional, Dict
from Crypto.Hash import MD5, SHA256  # Use pycryptodome for optimized hashing

# Define hashing functions for various algorithms
hash_functions = {
    'md5': hashlib.md5,
    'sha1': hashlib.sha1,
    'sha256': hashlib.sha256,
    'sha512': hashlib.sha512,
    'sha3_256': hashlib.sha3_256,
    'sha3_512': hashlib.sha3_512,
    'blake2b': hashlib.blake2b,
    'blake2s': hashlib.blake2s,
    'ripemd160': lambda data: hashlib.new('ripemd160', data).digest(),
    'whirlpool': lambda data: hashlib.new('whirlpool', data).digest()
}

def generate_hash(algorithm: str, input_bytes: bytes) -> str:
    hasher = hash_functions[algorithm]()
    hasher.update(input_bytes)
    return hasher.hexdigest()

def detect_hash_type(hash_str: str) -> Optional[str]:
    hash_len = len(hash_str)
    hash_length_mapping = {
        32: 'md5',
        40: 'sha1',
        64: 'sha256',
        128: 'sha512',
        64: 'sha3_256',
        128: 'sha3_512',
        64: 'blake2b',
        64: 'blake2s',
        40: 'ripemd160',
        64: 'whirlpool'
    }
    return hash_length_mapping.get(hash_len)

def is_zip2_hash(hash_str: str) -> bool:
    zip2_pattern = re.compile(r'^\$zip2\$\*\d+\*\d+\*\d+\*([0-9a-fA-F]{32,})\*.*\*.*\*$')
    return zip2_pattern.match(hash_str) is not None

def check_zip2_hashes(target_hash: str, show_attempts: bool):
    # Sample ZIP2 hash data (replace with actual data)
    zip_file_hashes = {
        "file1.txt": "example_hash1",
        "file2.txt": "example_hash2"
    }

    for file_name, file_hash in zip_file_hashes.items():
        if show_attempts:
            print(f"File: {file_name}, Hash: {file_hash}")
        if file_hash == target_hash:
            print(f"Hash match found in file: {file_name}")
            return
    print("No hash match found.")

async def login_attempt(session: aiohttp.ClientSession, username: str, password: str) -> bool:
    data = {username_param: username, password_param: password}
    try:
        async with session.post(target_url, data=data) as response:
            text = await response.text()
            if success_indicator in text:
                print(f"Successful login with username: {username} and password: {password}")
                return True
    except aiohttp.ClientError as e:
        print(f"Request failed: {e}")
    return False

async def worker(username: str, password: str, session: aiohttp.ClientSession):
    await login_attempt(session, username, password)

async def run_login_attempts(wordlist: List[str], num_threads: int):
    async with aiohttp.ClientSession(proxy=proxy) as session:
        tasks = []
        for username in wordlist:
            for password in wordlist:
                tasks.append(worker(username, password, session))
                if len(tasks) >= num_threads:
                    await asyncio.gather(*tasks)
                    tasks = []
        if tasks:
            await asyncio.gather(*tasks)

def load_wordlist(file_path: str) -> List[str]:
    with open(file_path, 'r') as file:
        return [line.strip() for line in file]

def brute_force(password_length: int, charset: str, hash_function: str, target_hash: str, show_attempts: bool, num_threads: int):
    charset_chars = list(charset)
    
    async def attempt_password(attempt: str) -> Optional[str]:
        if show_attempts:
            print(f"Trying password: {attempt}")
        if hash_matches(attempt.encode(), target_hash, hash_function):
            return f"Password found: {attempt}"
        return None

    async def worker(attempt: str, queue: asyncio.Queue):
        result = await attempt_password(attempt)
        if result:
            print(result)
            queue.put_nowait(result)

    async def run_brute_force():
        queue = asyncio.Queue()
        tasks = []
        for length in range(1, password_length + 1):
            for attempt in itertools.product(charset_chars, repeat=length):
                password = ''.join(attempt)
                tasks.append(worker(password, queue))
                if len(tasks) >= num_threads:
                    await asyncio.gather(*tasks)
                    tasks = []
        if tasks:
            await asyncio.gather(*tasks)

    asyncio.run(run_brute_force())

def hash_matches(word: bytes, target_hash: str, hash_function: str) -> bool:
    return generate_hash(hash_function, word) == target_hash

def main():
    global target_url
    global success_indicator
    global proxy

    parser = argparse.ArgumentParser(description="Password Cracker")
    parser.add_argument('hashfile', help="File containing the hash to crack")
    parser.add_argument('--wordlist', help="File containing the wordlist for attacks")
    parser.add_argument('--charset', default="alphanumeric", choices=["alphanumeric", "digits", "special"], help="Charset to use for brute-force attacks")
    parser.add_argument('--length', type=int, default=8, help="Length of passwords for brute-force attacks")
    parser.add_argument('--show-attempts', action='store_true', help="Show each password attempt")
    parser.add_argument('--threads', type=int, default=os.cpu_count(), help="Number of threads for brute-force attacks")
    parser.add_argument('--url', help="Target URL for login page (for login attacks)")
    parser.add_argument('--success-indicator', help="String that indicates a successful login (for login attacks)")
    parser.add_argument('--proxy', help="Proxy server to use for requests (format: http://user:pass@host:port)")

    args = parser.parse_args()
    target_hash = None
    if args.hashfile:
        with open(args.hashfile, 'r') as file:
            target_hash = file.readline().strip()

    if args.proxy:
        proxy = {
            'http': args.proxy,
            'https': args.proxy
        }

    if args.url and args.success_indicator:
        target_url = args.url
        success_indicator = args.success_indicator
        
        if args.wordlist:
            wordlist = load_wordlist(args.wordlist)
            asyncio.run(run_login_attempts(wordlist, args.threads))
        else:
            charset = {
                "alphanumeric": string.ascii_letters + string.digits,
                "digits": string.digits,
                "special": string.ascii_letters + string.digits + string.punctuation
            }[args.charset]
            brute_force(args.length, charset, None, None, args.show_attempts, args.threads)
    else:
        if is_zip2_hash(target_hash):
            check_zip2_hashes(target_hash, args.show_attempts)
        else:
            hash_type = detect_hash_type(target_hash)
            if hash_type is None:
                print("Error: Unrecognized hash length or format.")
                return

            hash_function = hash_type

            if args.wordlist:
                with open(args.wordlist, 'r') as file:
                    wordlist = [line.strip() for line in file]
                    for word in wordlist:
                        if args.show_attempts:
                            print(f"Trying password: {word}")
                        if hash_matches(word.encode(), target_hash, hash_function):
                            print(f"Password found: {word}")
                            return
                print("Password not found.")
            else:
                charset = {
                    "alphanumeric": string.ascii_letters + string.digits,
                    "digits": string.digits,
                    "special": string.ascii_letters + string.digits + string.punctuation
                }[args.charset]
                brute_force(args.length, charset, hash_function, target_hash, args.show_attempts, args.threads)

if __name__ == "__main__":
    main()

