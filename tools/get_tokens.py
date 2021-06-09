from typing import Union
import sys
import requests
import argparse
import logging
import base64


def retrieve_hashes(endpoint: str, token: str) -> Union[None, dict]:
    headers = {
        "Authorization": f"Bearer {token}",
        "CoronaCheck-Protocol-Version": "3.0",
    }
    result = requests.post(endpoint, headers=headers)
    if result.status_code == 200:
        return result.json()
    logging.error(f"{result.status_code} failed request for token {token}")
    return None


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="use id_token to retrieve identity hashes")
    parser.add_argument('--url',
                        default='https://holder-api.acc.coronacheck.nl/v4/holder/access_tokens',
                        type=str,
                        help='endpoint to receive identity hashes from'
    )
    config = parser.parse_args()

    for jwt_line in sys.stdin:
        jwt_token = jwt_line.replace('\n', '')
        hashes = retrieve_hashes(config.url, jwt_token)
        payload = hashes['payload']
        print(base64.b64decode(payload).decode())
