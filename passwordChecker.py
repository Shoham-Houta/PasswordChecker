import hashlib
import sys

import requests


def request_api_data(query_char: str) -> requests.Response:
    url: str = "https://api.pwnedpasswords.com/range/" + query_char
    result: requests.Response = requests.get(url)
    if result.status_code != 200:
        raise RuntimeError(f"Error fetching: {result.status_code}, check the api again")
    return result


def get_password_leak_count(hashes: requests.Response, hash_to_check: str) -> int:
    hashes = (line.split(":") for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password: str) -> int:
    hashed_password: str = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    key: str = hashed_password[:5]
    tail: str = hashed_password[5:]
    result: requests.Response = request_api_data(key)

    return get_password_leak_count(result, tail)

###############
def main(args):
    for password in args:
        count:int = pwned_api_check(password)
        if count:
            print(f"{password} was found {count} times..... probably should change it")
        else:
            print(f"{password} found {count}..... still good to go :)")
    return "done!"


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
