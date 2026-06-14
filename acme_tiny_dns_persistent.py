#!/usr/bin/env python3

# Loosely dased on these specifications :
# https://datatracker.ietf.org/doc/html/rfc8555
# https://datatracker.ietf.org/doc/draft-ietf-acme-dns-persist/

from argparse import ArgumentParser, Namespace
from base64 import urlsafe_b64encode
from binascii import unhexlify
from dataclasses import dataclass, asdict
from hashlib import sha256
from pathlib import Path
from subprocess import Popen, PIPE
from sys import exit
from time import sleep, time
from typing import Any, Protocol, Tuple
from urllib.parse import urlsplit, urlunsplit, urlencode
from urllib.request import HTTPError, Request, urlopen
import logging, json, os, re, stat, sys

DEFAULT_DNS_OVER_HTTPS_JSON = "https://dns.google/resolve"
DEFAULT_ACCOUNT_KEY_NAME = "account.key"
DEFAULT_DOMAIN_CRT_NAME = "domain.crt"
DEFAULT_DOMAIN_KEY_NAME = "domain.key"
DEFAULT_POLLING_RETRY_SEC = 10
DEFAULT_POLLING_TIMEOUT_SEC = 3600
DEFAULT_RATE_LIMITED_RETRY_SEC = 60

UTF8 = "utf-8"
HTTP_HEADER_LOCATION = "Location"
HTTP_HEADER_CONTENT_TYPE = "Content-Type"


class AppError(Exception):
    pass


def _openssl(args: list[str], input=None) -> bytes:
    stdin = None if input is None else PIPE
    proc = Popen(["openssl"] + args, stdin=stdin, stdout=PIPE, stderr=PIPE)
    out, err = proc.communicate(input)
    if proc.returncode != 0:
        raise AppError(f"Error running openssl command with {args=}: {err}")
    return out


class OpensslPrivateKey:
    file: Path

    def __init__(self, file: Path):
        self.file = file

    def new(self) -> None:
        _openssl(
            [
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:4096",
                "-out",
                str(self.file),
            ]
        )

    def modulus_exponent(self) -> Tuple[bytes, bytes]:
        out = _openssl(
            [
                "pkey",
                "-in",
                str(self.file),
                "-noout",
                "-text",
            ]
        )
        pub = re.search(
            r"modulus:[\s]*(?:00:)?([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)",
            _decode_utf8(out),
            re.MULTILINE | re.DOTALL,
        )
        if not pub:
            raise AppError(f"Could not parse public bytes from {self.file}")
        pub_mod, pub_exp = pub.groups()
        # convert to big-endian bytes
        pub_exp = "{:x}".format(int(pub_exp))
        if len(pub_exp) % 2:
            pub_exp = "0{}".format(pub_exp)
        pub_exp = unhexlify(pub_exp.encode(UTF8))
        pub_mod = re.sub(r"(\s|:)", "", pub_mod)
        pub_mod = unhexlify(pub_mod.encode(UTF8))
        return pub_mod, pub_exp

    def sign(self, data: bytes) -> bytes:
        return _openssl(
            [
                "pkeyutl",
                "-sign",
                "-inkey",
                str(self.file),
                "-rawin",
                "-digest",
                "sha256",  # ACME-spec
            ],
            input=data,
        )

    def csr_der(self, domains: list[str]) -> bytes:
        """https://datatracker.ietf.org/doc/html/rfc8555#section-7.6"""
        return _openssl(
            # requires openssl 1.1.1+
            [
                "req",
                "-new",
                "-sha256",
                "-key",
                str(self.file),
                "-subj",
                f"/CN={domains[0]}",
                "-addext",
                "subjectAltName={}".format(
                    ",".join([f"DNS:{domain}" for domain in domains])
                ),
                "-outform",
                "DER",
            ],
        )


def _decode_utf8(data: bytes) -> str:
    try:
        return data.decode(UTF8)
    except IOError as e:
        raise AppError(f"UTF-8 decode failed: {data}")


def _json_loads(data: str) -> Any:
    try:
        return json.loads(data)
    except ValueError as e:
        raise AppError(f"Json parsing failed: {data}")


@dataclass
class Reply:
    data: Any
    headers: dict[str, str]
    status: int


def _request(
    url: str,
    req_data: bytes | None,
    headers: dict[str, str] | None = None,
) -> Tuple[int, bytes, dict[str, str]]:
    if headers is None:
        headers = {}
    # method is auto-selected from data (None -> GET, otherwise POST)
    req = Request(url, data=req_data, headers=headers)
    try:
        with urlopen(req) as response:  # blocking request
            status = response.status
            headers = dict(response.headers)
            data = response.read()  # fully buffer using blocking read
    except HTTPError as e:
        raise e
    except IOError as e:
        raise AppError(f"Request IO error : {e}")
    logging.debug(f"HTTP reply: {status=} {headers=} {data=}")
    return status, data, headers


def _dns_over_https_json(
    provider: str,
    name: str,
    type: str,
) -> dict:
    """https://developers.google.com/speed/public-dns/docs/doh/json"""
    params = {"name": name, "type": type}
    headers = {"Accept": "application/dns-json"}
    url = urlunsplit(urlsplit(provider)._replace(query=urlencode(params)))
    _, data, _ = _request(url, None, headers)
    """
    {
        "AD": false,
        "Answer": [
            {
                "TTL": 232,
                "data": "142.251.142.14",
                "name": "google.com.",
                "type": 1
            }
        ],
        "CD": false,
        "Question": [
            {
                "name": "google.com.",
                "type": 1
            }
        ],
        "RA": true,
        "RD": true,
        "Status": 0,
        "TC": false
    }
    """
    return _json_loads(_decode_utf8(data))


ACME_AUTHORIZATIONS = "authorizations"
ACME_CERTIFICATE = "certificate"
ACME_CHALLENGES = "challenges"
ACME_DEACTIVATED = "deactivated"
ACME_DETAIL = "detail"
ACME_DNS = "dns"
ACME_DNS_PERSIST_01 = "dns-persist-01"
ACME_EXPIRED = "expired"
ACME_EXPIRES = "expires"
ACME_FINALIZE = "finalize"
ACME_IDENTIFIER = "identifier"
ACME_INVALID = "invalid"
ACME_ISSUER_DOMAIN_NAMES = "issuer-domain-names"
ACME_KID = "kid"
ACME_PENDING = "pending"
ACME_PROCESSING = "processing"
ACME_READY = "ready"
ACME_REVOKED = "revoked"
ACME_STATUS = "status"
ACME_TXT = "TXT"
ACME_TXT_TYPE = 16  # https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2
ACME_TYPE = "type"
ACME_URL = "url"
ACME_VALID = "valid"
ACME_VALIDATION_PERSIST = "_validation-persist"
ACME_VALUE = "value"


class AcmeClient:

    retries: int
    _directory: dict[str, Any]
    _account_key: OpensslPrivateKey
    _kid: str | None

    def __init__(
        self,
        account_key: OpensslPrivateKey,
        *,
        directory_url: str,
        retries: int,
    ):
        self._kid = None
        self._account_key = account_key
        self.retries = retries  # needs to be set before fetching dictionary
        self._directory = self.dictionary(directory_url)

    def dictionary(self, directory_url: str) -> dict[str, Any]:
        """
        {
            "PnuDTgQP-bo": "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417",
            "keyChange": "https://acme-staging-v02.api.letsencrypt.org/acme/key-change",
            "meta": {
                "caaIdentities": [
                    "letsencrypt.org"
                ],
                "profiles": {
                    "classic": "https://letsencrypt.org/docs/profiles#classic",
                    "shortlived": "https://letsencrypt.org/docs/profiles#shortlived",
                    "tlsclient": "https://letsencrypt.org/docs/profiles#tlsclient",
                    "tlsserver": "https://letsencrypt.org/docs/profiles#tlsserver"
                },
                "termsOfService": "https://letsencrypt.org/documents/LE-SA-v1.7-June-04-2026.pdf",
                "website": "https://letsencrypt.org/docs/staging-environment/"
            },
            "newAccount": "https://acme-staging-v02.api.letsencrypt.org/acme/new-acct",
            "newNonce": "https://acme-staging-v02.api.letsencrypt.org/acme/new-nonce",
            "newOrder": "https://acme-staging-v02.api.letsencrypt.org/acme/new-order",
            "renewalInfo": "https://acme-staging-v02.api.letsencrypt.org/acme/renewal-info",
            "revokeCert": "https://acme-staging-v02.api.letsencrypt.org/acme/revoke-cert"
        }
        """
        return self._request(directory_url, None).data

    @staticmethod
    def _base64(data: bytes) -> str:
        # encode using the URL and filesystem-safe Base64 alphabet
        result = urlsafe_b64encode(data)
        # strip the base64 end-padding characters '='
        return _decode_utf8(result).replace("=", "")

    def _nonce(self) -> str:
        return self._request(self._directory["newNonce"], None).headers["Replay-Nonce"]

    def _jwk(self) -> dict[str, str]:
        modulus, exponent = self._account_key.modulus_exponent()
        return {
            "e": self._base64(exponent),
            "kty": "RSA",
            "n": self._base64(modulus),
        }

    def new_account(
        self,
        *,
        tos_agreed: bool,
        only_return_existing: bool,
    ) -> dict[str, str]:
        rep = self._signed_request(
            self._directory["newAccount"],
            {
                "termsOfServiceAgreed": tos_agreed,
                "onlyReturnExisting": only_return_existing,
            },
            {"jwk": self._jwk()},
        )
        """
        Status: 200
        Headers: { "Location": "https://acme-staging-v02.api.letsencrypt.org/acme/acct/123456789" }
        Payload: {
            "createdAt": "2026-06-12T17:20:52Z",
            "key": { "e": "AQAB", "kty": "RSA", "n": "7TX...kLU" },
            "status": "valid"
        }
        """
        self._kid = rep.headers[HTTP_HEADER_LOCATION]  # store account for later use
        return {
            ACME_KID: self._kid,
            "result": "registration" if rep.status == 201 else "login",
            **rep.data,
        }

    def new_order(self, domains: list[str]) -> Tuple[str, dict[str, Any]]:
        rep = self._signed_request(
            self._directory["newOrder"],
            {
                "identifiers": [
                    {
                        "type": "dns",
                        "value": domain,
                    }
                    for domain in domains
                ]
            },
            None,
        )
        return rep.headers[HTTP_HEADER_LOCATION], rep.data

    def trigger_challenge(self, challenge_url: str) -> dict[str, Any]:
        return self._signed_request(challenge_url, {}, None).data

    def finalize_order(self, order_url: str, csr_der: bytes) -> dict[str, Any]:
        return self._signed_request(
            order_url,
            {"csr": self._base64(csr_der)},
            None,
        ).data

    def certificate_chain(self, certificate_url: str) -> str:
        return self._signed_request(certificate_url, None, None).data

    def post_as_get(self, url: str) -> dict[str, Any]:
        rep = self._signed_request(url, None, None)
        """
        ORDER
        Status can be "pending", "ready", "processing", "valid", and "invalid"

        {
            "authorizations": [
                "https://acme-staging-v02.api.letsencrypt.org/acme/authz/123456789/2006805483",
                "https://acme-staging-v02.api.letsencrypt.org/acme/authz/123456789/2006805493"
            ],
            "expires": "2026-06-19T18:58:21Z",
            "finalize": "https://acme-staging-v02.api.letsencrypt.org/acme/finalize/123456789/41076316153",
            "identifiers": [
                {
                    "type": "dns",
                    "value": "www.example.com"
                },
                {
                    "type": "dns",
                    "value": "example.com"
                }
            ],
            "status": "valid",
            # once finalize has been called, processing is done, and state is valid, this appears :
            "certificate": "https://acme-staging-v02.api.letsencrypt.org/acme/cert/2c4bc8d0c1ddd4e0e1e4963a294f613494c5"
        }

        AUTHZ
        status can be "pending", "valid", "invalid", "deactivated", "expired", and "revoked"

        {
            "challenges": [
                {
                    "issuer-domain-names": [
                        "letsencrypt.org"
                    ],
                    "status": "pending",
                    "type": "dns-persist-01",
                    "url": "https://acme-staging-v02.api.letsencrypt.org/acme/chall/123456789/2007080943/33NIXg"
                },
                {
                    "status": "pending",
                    "token": "Bl0...YKY",
                    "type": "tls-alpn-01",
                    "url": "https://acme-staging-v02.api.letsencrypt.org/acme/chall/123456789/2007080943/kAFLxw"
                },
                {
                    "status": "pending",
                    "token": "Bl0...YKY",
                    "type": "dns-01",
                    "url": "https://acme-staging-v02.api.letsencrypt.org/acme/chall/123456789/2007080943/t-gNBw"
                },
                {
                    "status": "pending",
                    "token": "Bl0...YKY",
                    "type": "http-01",
                    "url": "https://acme-staging-v02.api.letsencrypt.org/acme/chall/123456789/2007080943/0Fqhcg"
                }
            ],
            "expires": "2026-06-19T19:14:50Z",
            "identifier": {
                "type": "dns",
                "value": "example.com"
            },
            "status": "pending"
        }

        CHALLENGE (dns-persist-01)
        status can be "pending", "processing", "valid"and "invalid"

        {
            "issuer-domain-names": [
                "letsencrypt.org"
            ],
            "status": "pending",
            "type": "dns-persist-01",
            "url": "https://acme-staging-v02.api.letsencrypt.org/acme/chall/123456789/2007080943/33NIXg"
        }

        {
            "issuer-domain-names": [
                "letsencrypt.org"
            ],
            "status": "valid",
            "type": "dns-persist-01",
            "url": "https://acme-staging-v02.api.letsencrypt.org/acme/chall/123456789/2007080943/33NIXg",
            "validated": "2026-06-13T09:16:42Z",
            "validationRecord": [
                {
                    "addressUsed": "",
                    "hostname": ""www.example.com"
                }
            ]
        }

        CERTIFICATE with 'Content-Type': 'application/pem-certificate-chain'

            -----BEGIN CERTIFICATE-----
            MIIGJzCCBQ+gAwIBAgISLEvI0MHd1ODh5JY6KU9hNJTFMA0GCSqGSIb3DQEBCwUA
            ...
            SOFJ+hLnhzKODueBmIRitiZFlD84ylC2HIqvEiusTjUljnlrrT3+H7bzVA==
            -----END CERTIFICATE-----
            
            -----BEGIN CERTIFICATE-----
            MIIFETCCAvmgAwIBAgIQRWi894FoouBfrwFWfZWO7zANBgkqhkiG9w0BAQsFADBD
            ...
            YJlfyJg=
            -----END CERTIFICATE-----
            
            -----BEGIN CERTIFICATE-----
            MIIGKDCCBBCgAwIBAgIRAKYOL1Z3OCaTuowlAS/mVJgwDQYJKoZIhvcNAQELBQAw
            
            jgKO5JRQNGcnvW8cVYK5AMjgRGZE6V9IxECMeEwNEFA17qGcweG1Tb3IpYs=
            -----END CERTIFICATE-----

        """
        return rep.data

    def _signed_request(
        self,
        url: str,
        payload: dict[str, Any] | None,
        auth: dict[str, Any] | None,
    ) -> Reply:
        # get a new nonce for anti-replay protection, and add provided auth
        protected_input: dict[str, Any] = {
            "url": url,
            "alg": "RS256",
            "nonce": self._nonce(),
        }
        if auth is not None:
            protected_input.update(auth)
        elif self._kid is not None:
            protected_input.update({ACME_KID: self._kid})
        else:
            raise AppError("An account ID is required for this operation")

        # encoded data for signing and transmission
        protected_coded = self._base64(json.dumps(protected_input).encode(UTF8))
        payload_coded = ""
        if payload is not None:
            payload_coded = self._base64(json.dumps(payload).encode(UTF8))

        # prepare signature input and sign it with the private account key
        sig_input = f"{protected_coded}.{payload_coded}".encode(UTF8)
        sig_coded = self._base64(self._account_key.sign(sig_input))

        # build the final request payload and send the request
        data = json.dumps(
            {
                "protected": protected_coded,
                "payload": payload_coded,
                "signature": sig_coded,
            }
        ).encode(UTF8)
        return self._request(url, data)

    def _request(self, url: str, req_data: bytes | None) -> Reply:
        headers = {
            HTTP_HEADER_CONTENT_TYPE: "application/jose+json",
            "User-Agent": "acme-tiny-dns-persistent",
        }
        retry = self.retries
        start = time()
        while True:
            if time() - start > DEFAULT_POLLING_TIMEOUT_SEC:
                raise AppError(f"Request {url} took too long")

            # handle retries
            retry = retry - 1
            if retry < 0:
                raise AppError(f"ACME request exausted {self.retries} retries")

            # make a single request
            try:
                status, data, headers = _request(url, req_data, headers)
            except HTTPError as e:
                # handle ACME error payload
                e_data = json.load(e.fp)
                e_hdrs = dict(e.hdrs)
                logging.debug(f"ACME problem: {e_data=} {e_hdrs=}")
                if e_data[ACME_TYPE] == "urn:ietf:params:acme:error:badNonce":
                    logging.warning(f"ACME request `bad nonce` for {url}, retrying")
                    sleep(1)
                    continue
                if e_data[ACME_TYPE] == "urn:ietf:params:acme:error:rateLimited":
                    logging.warning(f"ACME request `rate limited` for {url}")
                    sleep(DEFAULT_RATE_LIMITED_RETRY_SEC)
                    continue
                raise AppError(
                    "ACME error status {} type {} : {}".format(
                        e_data[ACME_STATUS],
                        e_data[ACME_TYPE],
                        e_data[ACME_DETAIL],
                    )
                )

            # every ACME operation returns UTF-8 text
            data = _decode_utf8(data)

            # most ACME operation return JSON
            if headers.get(HTTP_HEADER_CONTENT_TYPE) == "application/json":
                data = _json_loads(data)

            if status not in [200, 201, 204]:
                raise AppError(
                    f"ACME request failed: {url=} {req_data=} {status=} {headers=} {data=}"
                )

            return Reply(data=data, headers=headers, status=status)

    @staticmethod
    def _has_dns_persist_txt(domain: str, *, resolver: str) -> bool:
        domain = f"{ACME_VALIDATION_PERSIST}.{domain}"
        answers = _dns_over_https_json(resolver, domain, ACME_TXT)
        try:
            answers = answers["Answer"]
        except KeyError:
            return False
        txt_records = (x for x in answers if x["type"] == ACME_TXT_TYPE)
        for txt_record in txt_records:
            # remove the terminating 'root dot' in the dns names for comparison
            if txt_record["name"].rstrip(".") == domain.rstrip("."):
                return True
        return False


def build_client(
    account_key_file: Path,
    directory_url: str,
    retries: int,
    *,
    create_account_key_if_missing: bool,
    allow_account_registration: bool,
) -> Tuple[AcmeClient, dict[str, str]]:
    # manage account key
    account_key = OpensslPrivateKey(account_key_file.expanduser())
    if not account_key.file.is_file():
        if not create_account_key_if_missing:
            raise AppError(
                f"Account key {account_key_file} missing and creation was not allowed"
            )
        account_key.new()
        logging.info(f"Generated account key `{account_key.file}`")

    # lookup account and register if needed
    client = AcmeClient(account_key, directory_url=directory_url, retries=retries)
    account = client.new_account(
        tos_agreed=True,
        only_return_existing=not allow_account_registration,
    )
    logging.info(
        "Got account {} with status `{}`".format(
            account[ACME_KID],
            account[ACME_STATUS],
        )
    )
    if account[ACME_STATUS] != ACME_VALID:
        raise AppError(
            "Could not use account {} with status `{}`".format(
                account[ACME_KID],
                account[ACME_STATUS],
            )
        )
    return client, account


# allows function typing
class _CheckRecordFn(Protocol):
    def __call__(
        self,
        args: Namespace,
        account_kid: str,
        client: AcmeClient,
        *,
        authz: dict[str, Any],
        dns_persist: dict[str, Any],
    ) -> None: ...


def _check_record(
    args: Namespace,
    account_kid: str,
    client: AcmeClient,
    *,
    authz: dict[str, Any],
    dns_persist: dict[str, Any],
) -> None:
    # display challenge information as JSON-line
    record = {
        ACME_DNS: f"{ACME_VALIDATION_PERSIST}.{authz[ACME_IDENTIFIER][ACME_VALUE]}",
        ACME_TYPE: ACME_TXT,
        ACME_VALUE: "{}; accounturi={}{}{}".format(
            dns_persist[ACME_ISSUER_DOMAIN_NAMES][0],
            account_kid,
            "; policy=wildcard" if args.policy_wildcard else "",
            (
                ""
                if args.persist_until is None
                else f"; persistUntil={args.persist_until}"
            ),
        ),
    }
    print(json.dumps(record))

    # wait until the desired record has been set
    logging.info(
        "Polling for {} record `{}` every {} seconds ...".format(
            ACME_TXT,
            record[ACME_DNS],
            DEFAULT_POLLING_RETRY_SEC,
        )
    )
    start = time()
    while not client._has_dns_persist_txt(
        authz[ACME_IDENTIFIER][ACME_VALUE],
        resolver=args.dns_over_https_json,
    ):
        if time() - start > DEFAULT_POLLING_TIMEOUT_SEC:
            raise AppError(
                f"Record polling for {authz[ACME_IDENTIFIER][ACME_VALUE]} took too long"
            )
        sleep(DEFAULT_POLLING_RETRY_SEC)
    logging.info(
        "Found {} record `{}` (only presence is verified)".format(
            ACME_TXT,
            record[ACME_DNS],
        )
    )


def cmd_authorize(args: Namespace) -> None:
    # check inputs
    if args.persist_until is not None and args.persist_until < int(time()):
        raise AppError("Persist-until must be an unix timestamp in the future")

    # setup account
    client, account = build_client(
        Path(args.account_key),
        args.directory_url,
        args.retries,
        create_account_key_if_missing=True,
        allow_account_registration=True,
    )

    # create a new "dummy" order to pre-validate the challenges
    _create_validated_order(
        args,
        account[ACME_KID],
        client,
        check_record_hook=_check_record,
    )


def _create_validated_order(
    args: Namespace,
    kid: str,
    client: AcmeClient,
    check_record_hook: _CheckRecordFn | None,
) -> Tuple[str, dict[str, Any]]:
    # place a new order
    ord_url, ord_data = client.new_order(args.domain)
    logging.info(
        "Got order {} with status `{}`".format(
            ord_url,
            ord_data[ACME_STATUS],
        )
    )

    # proces each authorization to display the records to set
    for auth_url in ord_data[ACME_AUTHORIZATIONS]:
        authz = client.post_as_get(auth_url)
        logging.info(
            "Got authz {} for `{}` with status `{}`".format(
                auth_url,
                authz[ACME_IDENTIFIER][ACME_VALUE],
                authz[ACME_STATUS],
            )
        )

        # lookup compatible challenge
        dns_persist = [
            challenge
            for challenge in authz[ACME_CHALLENGES]
            if challenge[ACME_TYPE] == ACME_DNS_PERSIST_01
        ]
        if len(dns_persist) == 0:
            raise AppError(
                "Could not find a `{}` for authz {}".format(
                    ACME_DNS_PERSIST_01,
                    auth_url,
                )
            )

        # call the check record hook if provided
        if check_record_hook is not None:
            check_record_hook(
                args,
                kid,
                client,
                authz=authz,
                dns_persist=dns_persist[0],
            )

        # trigger the challenge validation
        challenge = client.trigger_challenge(dns_persist[0][ACME_URL])
        logging.info(
            "Polling challenge {} for `{}` every {} seconds (current status `{}`)  ...".format(
                challenge[ACME_URL],
                authz[ACME_IDENTIFIER][ACME_VALUE],
                DEFAULT_POLLING_RETRY_SEC,
                challenge[ACME_STATUS],
            )
        )

        start = time()
        while challenge[ACME_STATUS] not in [ACME_VALID, ACME_INVALID]:
            if time() - start > DEFAULT_POLLING_TIMEOUT_SEC:
                raise AppError(f"Challenge {challenge[ACME_URL]} took too long")
            sleep(DEFAULT_POLLING_RETRY_SEC)
            challenge = client.post_as_get(challenge[ACME_URL])
        logging.info(
            "Challenge {} reached status `{}`".format(
                challenge[ACME_URL],
                challenge[ACME_STATUS],
            )
        )

        # check for "failed" authorization state
        if authz[ACME_STATUS] in [
            ACME_REVOKED,
            ACME_DEACTIVATED,
            ACME_EXPIRED,
            ACME_INVALID,
        ]:
            logging.error(
                "Authorization {} has failed state `{}`".format(
                    auth_url,
                    authz[ACME_STATUS],
                )
            )

    # wait for order to complete the autorization check
    logging.info(
        "Polling order {} every {} seconds (current status `{}`)  ...".format(
            ord_url,
            DEFAULT_POLLING_RETRY_SEC,
            ord_data[ACME_STATUS],
        )
    )
    start = time()
    while ord_data[ACME_STATUS] == ACME_PENDING:
        if time() - start > DEFAULT_POLLING_TIMEOUT_SEC:
            raise AppError(f"Order {ord_url} readiness took too long")
        sleep(DEFAULT_POLLING_RETRY_SEC)
        ord_data = client.post_as_get(ord_url)

    logging.info(
        "Order {} reached status `{}`".format(
            ord_url,
            ord_data[ACME_STATUS],
        )
    )

    # check for "failed" order state
    if ord_data[ACME_STATUS] == ACME_INVALID:
        raise AppError(
            "Order {} has failed state `{}`".format(
                ord_url,
                ord_data[ACME_STATUS],
            )
        )

    return ord_url, ord_data


def cmd_issue(args) -> None:
    # check inputs
    if len(args.domain) == 0:
        raise AppError("A certificate must have at least one domain")

    # reuse existing account
    client, account = build_client(
        Path(args.account_key),
        args.directory_url,
        args.retries,
        create_account_key_if_missing=False,
        allow_account_registration=False,
    )

    # ensure a domain_key is available
    domain_key = OpensslPrivateKey(Path(args.domain_key).expanduser())
    if not domain_key.file.is_file():
        domain_key.new()
        logging.info(f"Generated domain key `{domain_key.file}`")

    # build a CSR for the provided domains
    csr_der = domain_key.csr_der(args.domain)

    # create a new order from known-to-previously-validating challenges
    ord_url, order = _create_validated_order(
        args,
        account[ACME_KID],
        client,
        check_record_hook=None,
    )

    # work order to completion
    start = time()
    while True:
        if time() - start > DEFAULT_POLLING_TIMEOUT_SEC:
            raise AppError(f"Order {ord_url} completion took too long")

        order = client.post_as_get(ord_url)

        if order[ACME_STATUS] == ACME_READY:
            logging.info(f"Submitting certificate signing request for {args.domain}")
            order = client.finalize_order(order[ACME_FINALIZE], csr_der)

        elif order[ACME_STATUS] == ACME_PROCESSING:
            sleep(DEFAULT_POLLING_RETRY_SEC)

        elif order[ACME_STATUS] == ACME_VALID:
            break

        else:
            AppError(f"Order {ord_url} has status `{order[ACME_STATUS]}`")

    logging.info(f"Order is valid, fetching signed certificate for {args.domain}")
    print(client.certificate_chain(order[ACME_CERTIFICATE]))


def run(argv) -> None:
    parser = ArgumentParser()
    parser.add_argument(
        "--log-level",
        choices=["debug", "info", "warning", "error", "critical"],
        default="warning",
    )
    parser.add_argument("--account-key", default=DEFAULT_ACCOUNT_KEY_NAME)
    parser.add_argument("--retries", type=int, default=10)
    parser.add_argument(
        "--directory-url",
        default="https://acme-staging-v02.api.letsencrypt.org/directory",
    )
    parsers = parser.add_subparsers(dest="command")

    sub = parsers.add_parser("authorize")
    sub.set_defaults(func=cmd_authorize)
    sub.add_argument("--policy-wildcard", action="store_true")
    sub.add_argument("--persist-until", type=int)
    sub.add_argument("--dns-over-https-json", default=DEFAULT_DNS_OVER_HTTPS_JSON)
    sub.add_argument("domain", nargs="+")

    sub = parsers.add_parser("issue")
    sub.set_defaults(func=cmd_issue)
    sub.add_argument("--domain-key", default=DEFAULT_DOMAIN_KEY_NAME)
    sub.add_argument("domain", nargs="+")

    args = parser.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format="%(levelname)s %(message)s",
    )
    logging.debug(f"Arguments: {args}")

    if args.command is None:
        logging.error("No command provided")
        exit(1)

    args.func(args)


def main(argv) -> None:
    try:
        run(argv)
    except KeyboardInterrupt:
        logging.warning(f"Interrupted by user")
        exit(1)
    except AppError as e:
        logging.critical(f"Fatal: {e}")
        exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])
