# acme-tiny-dns-persistent

This is an opinionated tiny script to issue and renew TLS certs.

## Credits

All ACME key management and API for registration is straight
from of the [diafygi/acme-tiny](https://github.com/diafygi/acme-tiny)

## How to use

Install any version of `openssl` (3.0+) executable and make it available in path.

### Step 1 (once) : account key, account URL, dns proofs

This operation generates an account key, register an account with it, and gets
the required information for you to later set-up your persistent DNS proof. This
is inherently a "centralized operation" as there can be only one proof per
domain.

Run the script once on your central management station:

```shell
python3 acme_tiny_dns_persistent.py register
```

You will get this kind of output, and the `account_url` is the most important :

```json
{
    "account_url": "https://acme-staging-v02.api.letsencrypt.org/acme/acct/123456789",
    "created_at": "2026-06-06T20:43:08Z",
    "result": "found",
    "status": "valid",
    "instructions": 
            "Now Create a TXT record named `_validation-persist` at the root of
            your dns zone. The record value has following structure, adapted for
            your certificate registry :
            
            `CA_DOMAIN; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/ACCOUNTID`

            Example for the domain `example.com`, with LetsEncrypt registry, and
            a registered account url:
            
            `_validation-persist.example.com TXT letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/123456789`
             
            Then you can run the commands of this tool, to get a certificate for your
            example.com domain, using that ACME-compatible registry account"
}
```

Follow the instructions above (and the documentation of your DNS registrar) to
setup your DNS persistent record required for later, for each DNS zone you need.

### Step 2 (once per server, SECURED) : domain key, domain csr

Running this step on each server allows the domain key itself, to never leave
the server.

```shell
python3 acme_tiny_dns_persistent.py domains example.com www.example.com
```

Which returns with an exit code of `0` on success (and prints some info when log
level is INFO or below)

By default, the domain key is renewed each time this command is run (for better
security).

If you want, you can reuse the key by adding the `--keep-domain-key` option to
the `domains` command.

### Step 3 (once per server, UNPRIVILEGED) : issuing and renewing

First, export the account key to every host requiring it to then request actual
certificates.

You can use an unpriviledged user account, with the following permissions :

- **domain key** : prevent any access (better security)
- **domain csr** : read access (used to build requests)
- **account key** : read access (used to sign requests)

## Directory URLs

**May 2026** : `dns-persistent-01` is still a draft : follow the [forum
thread at LetsEncrypt](https://community.letsencrypt.org/t/dns-persist-01-deployment-status-and-timeline/246468/) for more news

Use the following option to specify the certificate provider you are using :

```shell
--acme-directory-url https://acme......
```

LetsEncrypt is the main free and public certificate authority, and is use by default

- [LetsEncrypt](https://letsencrypt.org)
  - staging/test `https://acme-staging-v02.api.letsencrypt.org/directory`
  - production `https://acme-v02.api.letsencrypt.org/directory`

Other ACME [rfc8555-compliant registries](https://datatracker.ietf.org/doc/html/rfc8555) may follow at their own pace

- [ZeroSSL](https://zerossl.com)
  - production : `https://acme.zerossl.com/v2/DV90`

- [SSL.com](https://www.ssl.com)
  - production RSA `https://acme.ssl.com/sslcom-dv-rsa`
  - production ECC `https://acme.ssl.com/sslcom-dv-ecc`

- [Google Public CA](https://docs.cloud.google.com/certificate-manager/docs/public-ca)
  - staging/test `https://dv.acme-v02.test-api.pki.goog/directory`
  - production `https://dv.acme-v02.api.pki.goog/directory`

## Goals and non-goals

- goals
  - a single external CLI dependency : [OpenSSL 3.0+](https://www.openssl.org/)
  - only support [supported Python versions](https://devguide.python.org/versions/)
  - no additional python library (only the standard library)
  - implementing **dns-persist-01** challenge **only** (contrary to `acme-tiny`
    which only supports)
  - allow doing the account registration separately : setup is done once
  - the account key can be distributed on every host requiring it to obtain or
    renew certificate for the authorized zone
- non-goals
  - any other feature (no webserver update, ...)

## Comparison with `acme-tiny`

### Allow for preliminary account registration

How does this work and what does it allow ?

- pre-generate an account key
- register it
- get the account url
- preset the DNS record manually
- distribute the account key using Ansible, etc
- setup renewal and client configuration independently
- let the hosts renew their certs with only ACME account key

### Support ACME `dns-persistent-01` challenge

This feature is not available in other minimal python ACME clients, as far as i know.

How does this work and what does it allow ?

- it could work with DNS registrars who do not provide API
- each host can obtain and renew cert using the account key **only**
- no hosts need access to the DNS provider API (for security and simplicity)

### Refactored to personnal taste

I refactored the code to make it more readable and understandable (for me at least !)

- added typing to help debugging
- defined constants to avoid duplication and errors
- split into smaller functions to make it simpler to reason about
- delete any non-goal features available, for simplicity, security and maintainability

## TODO

- Mention `persistUntil` in the documentation once the spec is stable
