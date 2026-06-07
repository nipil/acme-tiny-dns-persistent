#!/usr/bin/env python3

from argparse import ArgumentParser
from base64 import urlsafe_b64encode
from binascii import unhexlify
from hashlib import sha256
from pathlib import Path
from subprocess import Popen, PIPE
from sys import exit
from time import sleep
from typing import Any, Tuple
from urllib.request import Request, urlopen
import logging, json, re, sys

# ---- CONSTANTS -------------------------------------------------------------

ACME_ALG = "RS256"
ACME_CONTENT_TYPE = "application/jose+json"
ACME_DIR_NEW_ACCOUNT = "newAccount"
ACME_DIR_NEW_NONCE = "newNonce"
ACME_ERROR_BAD_NONCE = "urn:ietf:params:acme:error:badNonce"
ACME_KTY = "RSA"
ACME_REPLAY_NONCE = "Replay-Nonce"
ACME_TOS_AGREED = "termsOfServiceAgreed"
DEFAULT_ACCOUNT_KEY_NAME = "account.key"
DEFAULT_ACCOUNT_KEY_SIZE = 4096
DEFAULT_ACME_DIRECTORY_URL = "https://acme-staging-v02.api.letsencrypt.org/directory"
DEFAULT_BAD_NONCE_RETRY = 100
HTTP_HEADER_LOCATION = "Location"
RECORD_NAME = "_validation-persist"
USER_AGENT = "acme-tiny-dns-persistent"
UTF8 = "utf-8"

# ---- ERRORS ----------------------------------------------------------------


class AppError(Exception):
    pass


class AcmeBadNonce(Exception):
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


def request_with_json_reply(
    url: str, data, *, err_msg: str
) -> Tuple[dict, int, dict[str, str]]:
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
    except IOError as e:
        raise AppError(f"ACME request failed ({err_msg}) : {e}")
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
    return (data, status, headers)


def get_public_bytes_from_private_rsa_key(key_file: Path) -> Tuple[bytes, bytes]:
    # ask openssl to parse the key and print it as readable output
    out = run_command(
        # modernized openssl 3.0+ command, equivalent to
        # `openssl rsa -in account.key -noout -text`
        ["openssl", "pkey", "-in", str(key_file), "-noout", "-text"],
        err_msg="OpenSSL error while reading account key",
    )
    # extract the desirable parts: the modulus and exponent
    pub_pattern = re.compile(
        r"modulus:[\s]*(?:00:)?([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)"
    )
    m = pub_pattern.search(out.decode(UTF8), re.MULTILINE | re.DOTALL)
    if not m:
        raise AppError(f"Could not find public key in account_key {key_file}")
    pub_mod, pub_exp = m.groups()
    # convert to big-endian bytes
    pub_exp = "{0:x}".format(int(pub_exp))
    pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
    pub_exp = pub_exp.encode(UTF8)  # encode ascii text as bytes
    pub_exp = unhexlify(pub_exp)  # extract bytes from hex text
    pub_mod = re.sub(r"(\s|:)", "", pub_mod)  # remove known non-hex characters
    pub_mod = pub_mod.encode(UTF8)  # encode ascii text as bytes
    pub_mod = unhexlify(pub_mod)  # extract bytes from hex text
    return pub_mod, pub_exp


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


# ---- ACME -----------------------------------------------------------------


def acme_request(
    url: str, req_data=None, *, err_msg: str
) -> Tuple[dict[str, Any], int, dict[str, str]]:
    resp_data, status, headers = request_with_json_reply(url, req_data, err_msg=err_msg)
    if status == 400 and resp_data["type"] == ACME_ERROR_BAD_NONCE:
        raise AcmeBadNonce(f"ACME request `bad nonce` ({err_msg})")
    if status not in [200, 201, 204]:
        raise AppError(
            f"ACME request failed ({err_msg}): {url=} {req_data=} {status=} {resp_data=}"
        )
    return resp_data, status, headers


def acme_request_with_bad_nonce_retries(
    url: str, req_data=None, *, err_msg: str, retries: int
) -> Tuple[dict[str, Any], int, dict[str, str]]:
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


def acme_get_url_directory(url: str, *, retries: int):
    logging.debug("Getting ACME url directory...")
    directory, _, _ = acme_request_with_bad_nonce_retries(
        url, err_msg="getting directory urls", retries=retries
    )
    logging.debug(f"Directory found: {directory}")
    return directory
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
    _, _, headers = acme_request_with_bad_nonce_retries(
        new_nonce_url, err_msg=err_msg, retries=retries
    )
    nonce = headers[ACME_REPLAY_NONCE]
    logging.debug(f"Got new ACME nonce: {nonce}")
    return nonce


def acme_send_signed_request(
    url: str,
    payload: dict[str, Any],
    *,
    key_file: Path,
    jwk: dict[str, str],
    new_nonce_url: str,
    err_msg: str,
    retries: int,
):
    # get a new nonce for anti-replay protection, and build content
    new_nonce = acme_get_nonce(new_nonce_url, err_msg=err_msg, retries=retries)
    protected_coded = acme_encode_protected(url, jwk, new_nonce)
    payload_coded = acme_encode_payload(payload)
    # prepare signature input and sign it with the account key
    signature_input_coded = acme_encode_signature_input(protected_coded, payload_coded)
    signature_bytes = sign_with_key_file(signature_input_coded, key_file)
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


def acme_json_web_key_from_public_account_key(
    pub_mod: bytes, pub_exp: bytes
) -> dict[str, str]:
    # build the struct holding our RSA account key public parts
    return {
        "e": base64_encode_safe_for_url_and_filesystem(pub_exp),
        "kty": ACME_KTY,
        "n": base64_encode_safe_for_url_and_filesystem(pub_mod),
    }


def acme_encode_payload(payload: dict[str, Any] | None) -> str:
    if payload is None:
        return ""
    return base64_encode_safe_for_url_and_filesystem(json.dumps(payload).encode(UTF8))


def acme_encode_protected(
    url: str,
    jwk: dict[str, str],
    new_nonce: str,
) -> str:
    protected = {"url": url, "jwk": jwk, "alg": ACME_ALG, "nonce": new_nonce}
    # FIXME jwk becomes kid->location once we have tried to register and account is found
    # protected.update(
    #     {"jwk": jwk} if acct_headers is None else {"kid": acct_headers["Location"]}
    # )
    return base64_encode_safe_for_url_and_filesystem(json.dumps(protected).encode(UTF8))


def acme_encode_signature_input(protected_coded: str, payload_coded: str) -> bytes:
    return "{0}.{1}".format(protected_coded, payload_coded).encode(UTF8)


def acme_get_account_key_thumbprint(jwk: dict) -> str:
    # dump sorted and stripped, required for stable hashing
    accountkey_json = json.dumps(jwk, sort_keys=True, separators=(",", ":"))
    # build the sha256 of it and encode it
    thumbprint = sha256(accountkey_json.encode(UTF8)).digest()
    return base64_encode_safe_for_url_and_filesystem(thumbprint)


def acme_ensure_account_key_exists(key_file: Path, bits: int) -> None:
    if key_file.is_file():
        logging.info(f"Account key {key_file} already exists, skipping creation")
        return
    out = run_command(
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
    with open(key_file, "wb") as out_file:
        out_file.write(out)
    logging.info(f"Account key generated into {key_file}")


def acme_ensure_account_is_registered(
    key_file: Path,
    jwk: dict[str, str],
    *,
    new_account_url: str,
    new_nonce_url: str,
    retries: int,
):
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
    account, status, headers = acme_send_signed_request(
        new_account_url,
        register_payload,
        key_file=key_file,
        jwk=jwk,
        err_msg="Error registering account with public key",
        new_nonce_url=new_nonce_url,
        retries=retries,
    )
    # display register result
    logging.debug(f"Account registration reply: {account=} {status=} {headers=}")
    return {
        "result": "registered" if status == 201 else "found",
        "status": account["status"],
        "created_at": account["createdAt"],
        "account_url": headers[HTTP_HEADER_LOCATION],
    }


# ---- CLI ------------------------------------------------------------------


def cmd_register(args) -> None:
    # do the crypto
    key_file = Path(args.file).expanduser()
    acme_ensure_account_key_exists(key_file, args.bits)
    pub_mod, pub_exp = get_public_bytes_from_private_rsa_key(args.file)
    jwk = acme_json_web_key_from_public_account_key(pub_mod, pub_exp)
    # do the networking
    directory = acme_get_url_directory(
        args.acme_directory_url, retries=args.bad_nonce_retries
    )
    result = acme_ensure_account_is_registered(
        key_file,
        jwk,
        retries=args.bad_nonce_retries,
        new_account_url=directory[ACME_DIR_NEW_ACCOUNT],
        new_nonce_url=directory[ACME_DIR_NEW_NONCE],
    )
    # update result with instructions
    result.update(
        {
            "instructions": (
                f"Now Create a TXT record named `{RECORD_NAME}` at the root of your dns "
                "zone. The record value has following structure, adapted for your "
                "certificate registry : `REGISTRAR_DOMAIN; "
                "accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/ACCOUNTID`. "
                "Example for the domain `example.com`, with LetsEncrypt registry, and a "
                "registered account url: `_validation-persist.example.com TXT "
                "letsencrypt.org; "
                "accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/123456789`."
                "Then you can run the commands of this tool, to get a certificate for "
                "your example.com domain, using that ACME-compatible registry account"
            )
        }
    )
    # show to the user on a single line (easier for later parsing)
    print(json.dumps(result, sort_keys=True, indent=None))


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
    sub.add_argument("--file", default=DEFAULT_ACCOUNT_KEY_NAME)

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
    # main(["--log-level", "debug", "register"])
