from typing import Union
import sys
import requests
import argparse
import logging
import base64
import json


def retrieve_provider_details(providers_url: str) -> Union[None, dict]:
    r = requests.get(providers_url)
    if r.status_code != 200:
        logging.error(f"{r.status_code} failed to retrieve provider details")
        return None
    reply = r.json()
    payload = reply['payload']
    details = base64.b64decode(payload)
    provider_details = json.loads(details)
    provider_by_id = {
        d['provider_identifier']: d
        for d in provider_details['event_providers']
    }
    return provider_by_id


def get_event_details(provider_url, token) -> dict:
    h = {
        "Authorization": f"Bearer {token}",
        "CoronaCheck-Protocol-Version": "3.0",
    }
    r = requests.post(provider_url, headers=h)
    r.raise_for_status()
    details = r.json()
    payload = base64.b64decode(details['payload'])
    return json.loads(payload)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="use identity hashes to retrieve unomi and events from data providers")
    parser.add_argument('--providers_url',
                        default='https://holder-api.acc.coronacheck.nl/v4/holder/config_providers/',
                        type=str,
                        help='endpoint to receive provider details from'
    )
    config = parser.parse_args()

    providers = retrieve_provider_details(config.providers_url)

    for hashes_line in sys.stdin:
        hashes = json.loads(hashes_line)  #[:-1])

        provider_events = {}
        for token in hashes['tokens']:
            provider = token['provider_identifier']
            unomi_details = get_event_details(providers[provider]['unomi_url'], token['unomi'])
            event = {
                token['provider_identifier']: unomi_details
            }
            if unomi_details['informationAvailable']:
                event['event'] = get_event_details(providers[provider]['event_url'], token['event'])
            provider_events[provider] = event
        print(json.dumps(provider_events))
