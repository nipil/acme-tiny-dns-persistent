#!/usr/bin/env python3

from argparse import ArgumentParser
from base64 import urlsafe_b64encode
from binascii import unhexlify
from dataclasses import dataclass, asdict
from hashlib import sha256
from pathlib import Path
from subprocess import Popen, PIPE
from sys import exit
from time import sleep, time
from typing import Any
from urllib.request import HTTPError, Request, urlopen
import logging, json, os, re, stat, sys

# ---- CONSTANTS -------------------------------------------------------------

# application
DEFAULT_ACCOUNT_KEY_NAME = "account.key"
DEFAULT_ACCOUNT_KEY_SIZE = 4096
DEFAULT_ACME_DIRECTORY_URL = "https://acme-staging-v02.api.letsencrypt.org/directory"
DEFAULT_BAD_NONCE_RETRY = 100
DEFAULT_DOMAIN_CRT_NAME = "domain.crt"
DEFAULT_DOMAIN_CSR_NAME = "domain.csr"
DEFAULT_DOMAIN_KEY_NAME = "domain.key"
DEFAULT_DOMAIN_KEY_SIZE = 4096
DEFAULT_POLLING_RETRY_SEC = 10
DEFAULT_POLLING_TIMEOUT_SEC = 3600
DEFAULT_RATE_LIMITED_RETRY_SEC = 60

USER_AGENT = "acme-tiny-dns-persistent"
UTF8 = "utf-8"

# acme protocol
ACME_ALG = "RS256"
ACME_AUTHORIZATIONS = "authorizations"
ACME_CERTIFICATE = "certificate"
ACME_CONTENT_TYPE = "application/jose+json"
ACME_DNS_RECORD_NAME = "_validation-persist"
ACME_DIR_NEW_ACCOUNT = "newAccount"
ACME_DIR_NEW_NONCE = "newNonce"
ACME_DIR_NEW_ORDER = "newOrder"
ACME_ERROR_BAD_NONCE = "urn:ietf:params:acme:error:badNonce"
ACME_ERROR_RATE_LIMITED = "urn:ietf:params:acme:error:rateLimited"
ACME_EXPIRES = "expires"
ACME_FINALIZE = "finalize"
ACME_KTY = "RSA"
ACME_REPLAY_NONCE = "Replay-Nonce"
ACME_STATUS = "status"
ACME_STATUS_PENDING = "pending"
ACME_STATUS_PROCESSING = "processing"
ACME_TOS_AGREED = "termsOfServiceAgreed"
ACME_VALID = "valid"

HTTP_HEADER_LOCATION = "Location"

# ---- ERRORS ----------------------------------------------------------------


class AppError(Exception):
    pass


class AcmeError(Exception):
    pass


class AcmeBadNonce(AcmeError):
    pass


class AcmeRateLimited(AcmeError):
    pass


# ---- LIBRARY --------------------------------------------------------------


def base64_encode_safe_for_url_and_filesystem(data: bytes) -> str:
    # encode using the URL and filesystem-safe Base64 alphabet
    result = urlsafe_b64encode(data)
    # strip the base64 end-padding characters '='
    return result.decode(UTF8).replace("=", "")


def run_command(
    cmd: list[str], stdin=None, cmd_input=None, err_msg: str = "Command Line Error"
) -> bytes:
    logging.debug(f"Executing: {cmd=} {stdin=} {cmd_input=}")
    if stdin is not PIPE and cmd_input is not None:
        raise AppError("stdin and cmd_input are mutually exclusive")
    proc = Popen(cmd, stdin=stdin, stdout=PIPE, stderr=PIPE)
    out, err = proc.communicate(cmd_input)
    logging.debug(f"Executed: {proc.returncode=} {out=} {err=}")
    if proc.returncode != 0:
        raise AppError("{0}\n{1}".format(err_msg, err))
    return out


def generate_rsa_private_key(bits: int) -> bytes:
    logging.debug(f"Generating private key with {bits} bits")
    private_key = run_command(
        # modernized openssl 3.0+ command, equivalent to
        # `openssl genrsa 4096`
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            f"rsa_keygen_bits:{bits}",
        ]
    )
    logging.debug(f"Private key generated: {private_key}")
    return private_key


def save_private_file(private_file: Path, contents: bytes):
    logging.debug(f"Saving private file {private_file} with restrictive permissions")
    with open(private_file, "wb") as out_file:
        # SECURITY: by default, set to most restrictive : the user can change afterwards
        os.chmod(private_file, mode=stat.S_IRUSR | stat.S_IWUSR)
        out_file.write(contents)


def save_public_file(public_file: Path, contents: bytes):
    logging.debug(f"Saving public file {public_file} with standard permissions")
    with open(public_file, "wb") as out_file:
        os.chmod(
            public_file,
            mode=stat.S_IRUSR
            | stat.S_IWUSR
            | stat.S_IRGRP
            | stat.S_IWGRP
            | stat.S_IROTH,
        )
        out_file.write(contents)


@dataclass
class Reply:
    data: dict[str, Any]
    headers: dict[str, str]
    status: int


def request_with_json_reply(url: str, data, *, err_msg: str) -> Reply:
    headers = {
        "Content-Type": ACME_CONTENT_TYPE,
        "User-Agent": USER_AGENT,
    }
    req = Request(
        url,
        # method is auto-selected from data (None -> GET, otherwise POST)
        data=data,
        headers=headers,
    )
    logging.debug(f"HTTP request: {url=} {data=} {headers=}")
    try:
        with urlopen(req) as response:  # blocking request
            status = response.status
            headers = dict(response.headers)
            data = response.read()  # fully buffer using blocking read
    except HTTPError as e:
        raise AppError(f"Request HTTP error ({err_msg}) : {e}, with data {e.fp.read()}")
    except IOError as e:
        raise AppError(f"Request IO error ({err_msg}) : {e}")
    logging.debug(f"HTTP response: {status=} {headers=} {data=}")

    try:
        data = data.decode(UTF8)
    except IOError as e:
        raise AppError(f"ACME response UTF-8 decode failed ({err_msg}) : {data}")

    # ensure the reply JSON parsing will succeed even if empty instead of ignoring errors
    if len(data) == 0:
        data = "{}"

    try:
        data = json.loads(data)
    except ValueError as e:
        raise AppError(f"ACME response json parsing failed ({err_msg}) : {data}")
    return Reply(data=data, headers=headers, status=status)


@dataclass
class PublicKeyValues:
    modulus: bytes
    exponent: bytes


def get_public_bytes_from_private_rsa_key(key_file: Path) -> PublicKeyValues:
    # ask openssl to parse the key and print it as readable output
    out = run_command(
        # modernized openssl 3.0+ command, equivalent to
        # `openssl rsa -in account.key -noout -text`
        ["openssl", "pkey", "-in", str(key_file), "-noout", "-text"],
        err_msg="OpenSSL error while reading account key",
    )
    # extract the desirable parts: the modulus and exponent
    pub = re.search(
        r"modulus:[\s]*(?:00:)?([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)",
        out.decode(UTF8),
        re.MULTILINE | re.DOTALL,
    )
    if not pub:
        raise AppError(f"Could not find public key in account_key {key_file}")
    pub_mod, pub_exp = pub.groups()
    # convert to big-endian bytes
    pub_exp = "{0:x}".format(int(pub_exp))
    pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
    pub_exp = pub_exp.encode(UTF8)  # encode ascii text as bytes
    pub_exp = unhexlify(pub_exp)  # extract bytes from hex text
    pub_mod = re.sub(r"(\s|:)", "", pub_mod)  # remove known non-hex characters
    pub_mod = pub_mod.encode(UTF8)  # encode ascii text as bytes
    pub_mod = unhexlify(pub_mod)  # extract bytes from hex text
    return PublicKeyValues(modulus=pub_mod, exponent=pub_exp)


def sign_with_key_file(data: bytes, key_file: Path) -> bytes:
    logging.debug(f"Signing: {data}")
    signature_bytes = run_command(
        # modernized openssl 3.0+ command, equivalent to
        # `openssl dgst -sha256 -sign account.key`
        [
            "openssl",
            "pkeyutl",
            "-sign",
            "-inkey",
            str(key_file),
            "-rawin",
            "-digest",
            "sha256",
        ],
        stdin=PIPE,
        cmd_input=data,
        err_msg="OpenSSL Error while computing digest",
    )
    logging.debug(f"Signature: {signature_bytes}")
    return signature_bytes


def ensure_account_key_exists(account_key_file: Path, bits: int) -> None:
    if account_key_file.is_file():
        logging.info(
            f"Account key {account_key_file} already exists, skipping creation"
        )
        return
    account_key = generate_rsa_private_key(bits)
    save_private_file(account_key_file, account_key)
    logging.info(f"Account key generated into {account_key_file}")


def ensure_domain_key_exists(
    domain_key_file: Path, bits: int, keep_domain_key: bool
) -> None:
    if domain_key_file.is_file() and keep_domain_key:
        logging.info(f"Domain key {domain_key_file} already exists, skipping creation")
        return
    domain_key = generate_rsa_private_key(bits)
    save_private_file(domain_key_file, domain_key)
    logging.info(f"Domain key generated into {domain_key_file}")


# do not provide IP addresss as domains, they would be marked as domains in SAN !
def create_domain_signing_request(domain_key_file: Path, domains: list[str]) -> bytes:
    logging.debug(f"Creating signing request using {domain_key_file} for {domains}")
    if len(domains) == 0:
        raise AppError("A certificate signing request must have at least one domain")
    # use first provided domain as CN (common name)
    common_name = "CN={}".format(domains[0])
    # prepare SAN record like `subjectAltName = DNS:yoursite.com, DNS:www.yoursite.com`
    domains = [f"DNS:{domain}" for domain in domains]
    san_alternate_name = "subjectAltName = {}".format(", ".join(domains))
    # build actual
    signing_request = run_command(
        # requires openssl 1.1.1+
        [
            "openssl",
            "req",
            "-new",
            "-sha256",
            "-key",
            str(domain_key_file),
            "-subj",
            f"/{common_name}",
            "-addext",
            san_alternate_name,
        ],
        err_msg="OpenSSL Error while generating certificate signing request",
    )
    logging.debug(f"Signing request created: {signing_request}")
    return signing_request


def get_csr_domains(csr_file: Path) -> list[str]:
    logging.debug(f"Getting list of domains from CSR {csr_file}")
    domains = set()
    # get CSR content as encoded text
    domain_csr = run_command(
        ["openssl", "req", "-in", str(csr_file), "-noout", "-text"],
        err_msg=f"OpenSSL Error while parsing certificate signing request {csr_file}",
    )
    # decode as utf-8
    try:
        domain_csr = domain_csr.decode(UTF8)
    except IOError as e:
        raise AppError(f"Domain certificate UTF-8 decode failed for {csr_file} : {e}")
    # extract domain from CN field if present
    common_name = re.search(r"Subject:.*? CN\s?=\s?([^\s,;/]+)", domain_csr)
    if common_name is not None:
        common_name = common_name.group(1)
        logging.debug(f"Found {common_name} CN in CSR")
        domains.add(common_name)
    # extract domains from SAN field
    subject_alt_names = re.search(
        r"X509v3 Subject Alternative Name: (?:critical)?\n +([^\n]+)\n",
        domain_csr,
        re.MULTILINE | re.DOTALL,
    )
    if subject_alt_names is not None:
        subject_alt_names = subject_alt_names.group(1)
        san_re = re.compile("DNS:(.*)")
        for san in subject_alt_names.split(","):
            san = san.strip()
            domain = san_re.fullmatch(san)
            if domain is None:
                logging.warning(
                    f"Could not extract domain from {san} while parsing CSR"
                )
                continue
            domain = domain.group(1)
            logging.debug(f"Found {domain} SAN in CSR")
            domains.add(domain)
    return sorted(domains)


# ---- ACME -----------------------------------------------------------------


def acme_request(url: str, req_data=None, *, err_msg: str) -> Reply:
    resp = request_with_json_reply(url, req_data, err_msg=err_msg)
    if resp.status == 400 and resp.data["type"] == ACME_ERROR_BAD_NONCE:
        raise AcmeBadNonce(f"ACME request `bad nonce` ({err_msg}) for {url}")
    if resp.status == 503 and resp.data["type"] == ACME_ERROR_RATE_LIMITED:
        raise AcmeRateLimited(f"ACME request `rate limited` ({err_msg}) for {url}")
    if resp.status not in [200, 201, 204]:
        raise AppError(f"ACME request failed ({err_msg}): {url=} {req_data=} {resp=}")
    return resp


def acme_request_with_bad_nonce_retries(
    url: str, req_data=None, *, err_msg: str, retries: int
) -> Reply:
    retry = retries
    while True:
        retry = retry - 1
        if retry < 0:
            raise AppError(f"ACME request retry exausted")
        try:
            return request_with_json_reply(url, req_data, err_msg=err_msg)
        except AcmeBadNonce as e:
            logging.warning(e)
            sleep(1)
            continue
        except AcmeRateLimited as e:
            logging.warning(e)
            sleep(DEFAULT_RATE_LIMITED_RETRY_SEC)


def acme_get_url_directory(url: str, *, retries: int) -> dict[str, Any]:
    logging.debug("Getting ACME url directory...")
    directory = acme_request_with_bad_nonce_retries(
        url, err_msg="getting directory urls", retries=retries
    )
    logging.debug(f"Directory found: {directory.data=}")
    return directory.data
    # {'PnuDTgQP-bo': 'https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417',
    #  'keyChange': 'https://acme-staging-v02.api.letsencrypt.org/acme/key-change',
    #  'meta': {'caaIdentities': ['letsencrypt.org'],
    #           'profiles': {'classic': 'https://letsencrypt.org/docs/profiles#classic',
    #                        'shortlived': 'https://letsencrypt.org/docs/profiles#shortlived',
    #                        'tlsclient': 'https://letsencrypt.org/docs/profiles#tlsclient',
    #                        'tlsserver': 'https://letsencrypt.org/docs/profiles#tlsserver'},
    #           'termsOfService': 'https://letsencrypt.org/documents/LE-SA-v1.7-June-04-2026.pdf',
    #           'website': 'https://letsencrypt.org/docs/staging-environment/'},
    #  'newAccount': 'https://acme-staging-v02.api.letsencrypt.org/acme/new-acct',
    #  'newNonce': 'https://acme-staging-v02.api.letsencrypt.org/acme/new-nonce',
    #  'newOrder': 'https://acme-staging-v02.api.letsencrypt.org/acme/new-order',
    #  'renewalInfo': 'https://acme-staging-v02.api.letsencrypt.org/acme/renewal-info',
    #  'revokeCert': 'https://acme-staging-v02.api.letsencrypt.org/acme/revoke-cert'}


def acme_get_nonce(new_nonce_url: str, *, err_msg: str, retries: int) -> str:
    logging.debug("Getting new nonce...")
    nonce = acme_request_with_bad_nonce_retries(
        new_nonce_url, err_msg=err_msg, retries=retries
    )
    nonce = nonce.headers[ACME_REPLAY_NONCE]
    logging.debug(f"Got new ACME nonce: {nonce}")
    return nonce


def acme_send_signed_request(
    url: str,
    payload: dict[str, Any] | None,
    *,
    account_key_file: Path,
    identification: dict[str, Any],
    new_nonce_url: str,
    err_msg: str,
    retries: int,
) -> Reply:
    # get a new nonce for anti-replay protection, and build content
    new_nonce = acme_get_nonce(new_nonce_url, err_msg=err_msg, retries=retries)
    # build protected content
    protected = {"url": url, "alg": ACME_ALG, "nonce": new_nonce}
    protected.update(identification)
    protected_coded = base64_encode_safe_for_url_and_filesystem(
        json.dumps(protected).encode(UTF8)
    )
    # build encoded payload
    payload_coded = acme_encode_payload(payload)
    # prepare signature input and sign it with the account key
    signature_input_coded = acme_encode_signature_input(protected_coded, payload_coded)
    signature_bytes = sign_with_key_file(signature_input_coded, account_key_file)
    # build the final request payload and send the request
    data = json.dumps(
        {
            "protected": protected_coded,
            "payload": payload_coded,
            "signature": base64_encode_safe_for_url_and_filesystem(signature_bytes),
        }
    )
    logging.debug(f"Final signed request payload: {data=}")
    data = data.encode(UTF8)
    return acme_request_with_bad_nonce_retries(
        url, data, err_msg=err_msg, retries=retries
    )


def acme_jwk_from_public_key(pub_key: PublicKeyValues) -> dict[str, str]:
    # build the "json web key" struct holding our RSA account key public parts
    return {
        "e": base64_encode_safe_for_url_and_filesystem(pub_key.exponent),
        "kty": ACME_KTY,
        "n": base64_encode_safe_for_url_and_filesystem(pub_key.modulus),
    }


def acme_encode_payload(payload: dict[str, Any] | None) -> str:
    if payload is None:
        return ""
    return base64_encode_safe_for_url_and_filesystem(json.dumps(payload).encode(UTF8))


def acme_identification_jwk(jwk: dict[str, str]) -> dict[str, Any]:
    # when the account does not exist (before register)
    # when the account has been found (before login)
    # `jwk` is the public key stuff :
    return {"jwk": jwk}


def acme_identification_kid(kid: str) -> dict[str, Any]:
    # when the account exists `kid` contains `account_url` like
    # https://acme-staging-v02.api.letsencrypt.org/acme/acct/123456789
    return {"kid": kid}


def acme_encode_signature_input(protected_coded: str, payload_coded: str) -> bytes:
    return "{0}.{1}".format(protected_coded, payload_coded).encode(UTF8)


def acme_get_account_key_thumbprint(jwk: dict) -> str:
    # dump sorted and stripped, required for stable hashing
    accountkey_json = json.dumps(jwk, sort_keys=True, separators=(",", ":"))
    # build the sha256 of it and encode it
    thumbprint = sha256(accountkey_json.encode(UTF8)).digest()
    return base64_encode_safe_for_url_and_filesystem(thumbprint)


@dataclass
class AcmeAccountInfo:
    account_url: str
    created_at: str
    source: str
    status: str
    instructions: str | None


def acme_ensure_account_is_registered(
    account_key_file: Path,
    jwk: dict[str, str],
    *,
    new_account_url: str,
    new_nonce_url: str,
    retries: int,
) -> AcmeAccountInfo:
    """
    On first call, status = 200, which means account was registered
    On following calls, status = 201, which means account was found

    The header 'Location' holds the account url associated with key:
    https://acme-staging-v02.api.letsencrypt.org/acme/acct/299856733

    This URL will to be used as `kid` for later signed requests,
    instead of "jwk" as used when registering/looking up as here.

    The returned value is a dictionary with the following fields:
    - "key": { "kty": "RSA", "n": "jam...AmU", "e": "A..B" }
    - "createdAt": "2026-06-06T17:44:30Z"  # of registration
    - "status": "valid"
    """
    logging.debug("Registering account...")
    # prepare an account payload without email contact
    register_payload = {ACME_TOS_AGREED: True}
    account = acme_send_signed_request(
        new_account_url,
        register_payload,
        account_key_file=account_key_file,
        identification=acme_identification_jwk(jwk),
        err_msg="Error registering account with public key",
        new_nonce_url=new_nonce_url,
        retries=retries,
    )
    # display register result
    logging.debug(
        f"Account registration reply: {account.data=} {account.status=} {account.headers=}"
    )
    return AcmeAccountInfo(
        account_url=account.headers[HTTP_HEADER_LOCATION],
        created_at=account.data["createdAt"],
        source="registered" if account.status == 201 else "found",
        status=account.data[ACME_STATUS],
        instructions=(
            f"Now Create a TXT record named `{ACME_DNS_RECORD_NAME}` at the root of your dns "
            "zone. The record value has following structure, adapted for your "
            "certificate registry : `REGISTRAR_DOMAIN; "
            "accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/ACCOUNTID`. "
            "Example for the domain `example.com`, with LetsEncrypt registry, and a "
            "registered account url: `_validation-persist.example.com TXT "
            "letsencrypt.org; "
            "accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/123456789`."
            "Then you can run the commands of this tool, to get a certificate for "
            "your example.com domain, using that ACME-compatible registry account"
        ),
    )


def acme_create_new_order(
    new_order_url: str,
    domains: list[str],
    *,
    account_key_file: Path,
    identification: dict[str, Any],
    new_nonce_url: str,
    err_msg: str,
    retries: int,
) -> Reply:
    logging.debug(f"Creating ACME order for {domains=}")
    payload = [{"type": "dns", "value": domain} for domain in domains]
    payload = {"identifiers": payload}
    order = acme_send_signed_request(
        new_order_url,
        payload,
        account_key_file=account_key_file,
        identification=identification,
        err_msg=err_msg,
        new_nonce_url=new_nonce_url,
        retries=retries,
    )
    logging.debug(f"Order created: {order=}")
    return order
    # status: 201
    # data: {
    #     'status': 'pending',
    #     'expires': '2026-06-14T15: 55: 35Z',
    #     'identifiers': [
    #         {'type': 'dns', 'value': 'example.com'},
    #         {'type': 'dns', 'value': 'www.example.com'}
    #     ],
    #     'authorizations':
    #     [
    #         'https://acme-staging-v02.api.letsencrypt.org/acme/authz/123456789/1870853033',
    #         'https://acme-staging-v02.api.letsencrypt.org/acme/authz/123456789/1870853043'
    #     ],
    #     'finalize': 'https://acme-staging-v02.api.letsencrypt.org/acme/finalize/123456789/40530936783'
    # }
    #
    # notable_headers: {
    #  'Boulder-Requester': '123456789',
    #  'Link': '<https://acme-staging-v02.api.letsencrypt.org/directory>;rel="index"',
    #  'Location': 'https://acme-staging-v02.api.letsencrypt.org/acme/order/123456789/40530936783',
    #  'Replay-Nonce': 'Rj...............................................yI',
    # }


def acme_poll_until_status_not_in(
    url: str,
    wait_statuses: list[str],
    *,
    account_key_file: Path,
    identification: dict[str, Any],
    new_nonce_url: str,
    err_msg: str,
    retries: int,
) -> Reply:
    logging.debug(f"Polling {url} until status is not in  for {wait_statuses=}")
    timeout_sec = DEFAULT_POLLING_TIMEOUT_SEC
    start = time()
    while True:
        if time() - start > DEFAULT_POLLING_TIMEOUT_SEC:
            raise AppError(
                f"Polling timeout ({timeout_sec} seconds) reached: {err_msg}"
            )
        result = acme_send_signed_request(
            url,
            None,
            account_key_file=account_key_file,
            identification=identification,
            err_msg=err_msg,
            new_nonce_url=new_nonce_url,
            retries=retries,
        )
        logging.debug(f"Polling {url} result: {result=}")
        status = result.data[ACME_STATUS]
        if status in wait_statuses:
            sleep(DEFAULT_POLLING_RETRY_SEC)
            logging.debug(f"Time elapsed: {int(time() - start)}")
            continue
        logging.debug(f"Polling {url} finished with status {status}")
        return result


# ---- CLI ------------------------------------------------------------------


def cmd_register(args) -> None:
    # do the crypto
    account_key_file = Path(args.account_key).expanduser()
    ensure_account_key_exists(account_key_file, args.bits)
    pub_key_values = get_public_bytes_from_private_rsa_key(args.account_key)
    jwk = acme_jwk_from_public_key(pub_key_values)
    # do the networking
    directory = acme_get_url_directory(
        args.acme_directory_url, retries=args.bad_nonce_retries
    )
    result = acme_ensure_account_is_registered(
        account_key_file,
        jwk,
        retries=args.bad_nonce_retries,
        new_account_url=directory[ACME_DIR_NEW_ACCOUNT],
        new_nonce_url=directory[ACME_DIR_NEW_NONCE],
    )
    # show to the user on a single line (easier for later parsing)
    print(json.dumps(asdict(result), sort_keys=True, indent=None))


def cmd_domains(args) -> None:
    # generate domain key if required
    domain_key_file = Path(args.domain_key).expanduser()
    ensure_domain_key_exists(domain_key_file, args.bits, args.keep_domain_key)
    # generate certificate signing request
    domain_csr_file = Path(args.domain_csr).expanduser()
    domain_csr = create_domain_signing_request(domain_key_file, args.domain)
    save_public_file(domain_csr_file, domain_csr)
    logging.info(
        f"Certificate signing request {domain_csr_file} generated using {domain_key_file} for domains {args.domain}"
    )


def cmd_certificate(args) -> None:
    # get domains
    domain_csr_file = Path(args.domain_csr).expanduser()
    domains = get_csr_domains(domain_csr_file)
    # lookup urls
    directory = acme_get_url_directory(
        args.acme_directory_url, retries=args.bad_nonce_retries
    )
    # identification
    account_key_file = Path(args.account_key).expanduser()
    identification = acme_identification_kid(args.account_url)
    # create the order
    order = acme_create_new_order(
        directory[ACME_DIR_NEW_ORDER],
        domains,
        account_key_file=account_key_file,
        retries=args.bad_nonce_retries,
        new_nonce_url=directory[ACME_DIR_NEW_NONCE],
        identification=identification,
        err_msg="Error creating new order",
    )
    logging.info(
        "Created Order {} which expires {} with authorizations {}".format(
            order.headers[HTTP_HEADER_LOCATION],
            order.data[ACME_EXPIRES],
            order.data[ACME_AUTHORIZATIONS],
        )
    )
    # TODO: process authorizations ?
    # TODO: convert CSR to DER format
    # TODO: finalize
    #  poll the order to monitor when it's done
    finished_order = acme_poll_until_status_not_in(
        order.headers[HTTP_HEADER_LOCATION],
        [ACME_STATUS_PENDING, ACME_STATUS_PROCESSING],
        account_key_file=account_key_file,
        retries=args.bad_nonce_retries,
        new_nonce_url=directory[ACME_DIR_NEW_NONCE],
        identification=identification,
        err_msg="Error polling order",
    )
    logging.critical(f"Order complete: {finished_order=}")
    # check for success
    if finished_order.data[ACME_STATUS] != ACME_VALID:
        raise AppError("Order failed: {0}".format(finished_order.data))
    # download the certificate
    certificate = acme_send_signed_request(
        finished_order.data[ACME_CERTIFICATE],
        None,
        account_key_file=account_key_file,
        retries=args.bad_nonce_retries,
        new_nonce_url=directory[ACME_DIR_NEW_NONCE],
        identification=identification,
        err_msg="Error downloading certificate",
    )
    logging.critical(f"Certificate received: {certificate=}")


def run(argv) -> None:
    parser = ArgumentParser()
    parser.add_argument(
        "--log-level",
        choices=["debug", "info", "warning", "error", "critical"],
        default="warning",
    )
    parser.add_argument(
        "--bad-nonce-retries", type=int, default=DEFAULT_BAD_NONCE_RETRY
    )
    parser.add_argument("--acme-directory-url", default=DEFAULT_ACME_DIRECTORY_URL)
    parsers = parser.add_subparsers(dest="command")

    sub = parsers.add_parser("register")
    sub.set_defaults(func=cmd_register)
    sub.add_argument("--bits", type=int, default=DEFAULT_ACCOUNT_KEY_SIZE)
    sub.add_argument("--account-key", default=DEFAULT_ACCOUNT_KEY_NAME)

    sub = parsers.add_parser("domains")
    sub.set_defaults(func=cmd_domains)
    sub.add_argument("--bits", type=int, default=DEFAULT_DOMAIN_KEY_SIZE)
    sub.add_argument("--domain-key", default=DEFAULT_DOMAIN_KEY_NAME)
    sub.add_argument("--keep-domain-key", action="store_true")
    sub.add_argument("--domain-csr", default=DEFAULT_DOMAIN_CSR_NAME)
    sub.add_argument("domain", nargs="+")

    sub = parsers.add_parser("certificate")
    sub.set_defaults(func=cmd_certificate)
    sub.add_argument("--domain-csr", default=DEFAULT_DOMAIN_CSR_NAME)
    sub.add_argument("--account-key", default=DEFAULT_ACCOUNT_KEY_NAME)
    sub.add_argument("--account-url", required=True)
    sub.add_argument("--domain-crt", default=DEFAULT_DOMAIN_CRT_NAME)

    args = parser.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format="%(levelname)s %(message)s",
    )

    if args.command is None:
        logging.error("No command provided")
        exit(1)

    args.func(args)


def main(argv) -> None:
    try:
        run(argv)
    except AppError as e:
        logging.critical(f"Fatal: {e}")
        exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])
