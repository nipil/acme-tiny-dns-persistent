# acme-tiny-dns-persistent

This is an opinionated tiny script to issue and renew TLS certs.

This tool only requires :

- the standard python 3.10+ library (no pip, nothing)
- the openssl 3.0+ command-line tool (available in path)

What is ACME `dns-persist-01` challenge and why is it good ?

- it could work with DNS registrars who do not provide API
- each host can obtain and renew cert using the account key **only**
- no hosts need access to the DNS provider API (for security and simplicity)

**May 2026** : `dns-persist-01` is still a draft : for more news you can
follow the [forum thread at LetsEncrypt](https://community.letsencrypt.org/t/dns-persist-01-deployment-status-and-timeline/246468/)

## Credits, goals and non-goals

All ACME key management and API for registration is straight from of the
[diafygi/acme-tiny](https://github.com/diafygi/acme-tiny)

Goals

- [OpenSSL 3.0+](https://www.openssl.org/) as single external dependency
- only for [supported Python versions](https://devguide.python.org/versions/)
- no additional python library (only the standard library)
- implementing **dns-persist-01** challenge **only**
- allow preparing account registration and domain validation once
- allow renewing domain key on each certificate issuance

Non-goals

- installing certificates, configuring web servers ...
- distributing shared account key, inventory, ...
- any other feature (no webserver configuration, ...)

## Usage and options

Common options for all commands

```text
  options:
  --log-level {debug,info,warning,error,critical}
  --polling-retry-sec POLLING_RETRY_SEC
  --polling-timeout-sec POLLING_TIMEOUT_SEC
  --rate-limited-retry-sec RATE_LIMITED_RETRY_SEC
  --account-key ACCOUNT_KEY
  --retries RETRIES
  --directory-url DIRECTORY_URL
```

**IMPORTANT**: logging prints on stderr while useful output (records, certificates) are printed on stdout.

Options for `authorize` command

```text
  positional arguments:
    domain

  options:
    --policy-wildcard
    --persist-until PERSIST_UNTIL
    --dns-over-https-json DNS_OVER_HTTPS_JSON
```

Options for `issue` command

```text
positional arguments:
  domain

options:
  --domain-key DOMAIN_KEY
```

You can use `--log-level info` to get more information during progress. Sample output (logging only) :

```text
INFO Got account https://acme-staging-v02.api.letsencrypt.org/acme/acct/123456789 with status `valid`
INFO Got order https://acme-staging-v02.api.letsencrypt.org/acme/order/123456789/41235445923 with status `pending`
INFO Got authz https://acme-staging-v02.api.letsencrypt.org/acme/authz/123456789/2043014233 for `www.example.com` with status `pending`
INFO Polling challenge https://acme-staging-v02.api.letsencrypt.org/acme/chall/123456789/2043014233/LzerBw for `www.example.com` every 10 seconds (current status `pending`)  ...
INFO Challenge https://acme-staging-v02.api.letsencrypt.org/acme/chall/123456789/2043014233/LzerBw reached status `valid`
INFO Got authz https://acme-staging-v02.api.letsencrypt.org/acme/authz/123456789/2043014243 for `example.com` with status `pending`
INFO Polling challenge https://acme-staging-v02.api.letsencrypt.org/acme/chall/123456789/2043014243/okCLzQ for `example.com` every 10 seconds (current status `pending`)  ...
INFO Challenge https://acme-staging-v02.api.letsencrypt.org/acme/chall/123456789/2043014243/okCLzQ reached status `valid`
INFO Polling order https://acme-staging-v02.api.letsencrypt.org/acme/order/123456789/41235445923 every 10 seconds (current status `pending`)  ...
INFO Order https://acme-staging-v02.api.letsencrypt.org/acme/order/123456789/41235445923 reached status `ready`
INFO Submitting certificate signing request for ['example.com', 'www.example.com']
INFO Order is valid, fetching signed certificate for ['example.com', 'www.example.com']
```

## How to use

### Step 1 (`authorize`) : account key, account URL, dns proofs

**IMPORTANT**: The ACME account private key becomes the new "crown jewel"
— if it's compromised, an attacker could reuse your persistent record.

This operation generates an account key, register an ACME account with it, and
shows the required information for you to set-up your persistent DNS proof. This
is inherently a "centralized operation" as there can be only one proof per
domain. This operation requires **you** to have access to your DNS zone : by
design, this tool does *not* need any access to your DNS zone (principle of
least privilege)

Run the script once on your central management station :

```shell
python3 acme_tiny_dns_persistent.py authorize example.com www.example.com
```

An ACME account key is created if none exists at the target `--account-key`
location. You will get then get the kind of output below, then the program will
poll the DNS to check these are *present* before continuing :

```json
{"dns": "_validation-persist.example.com", "type": "TXT", "value": "letsencrypt.org; accounturi=https://acme-staging-v02.api.letsencrypt.org/acme/acct/123456789"}
{"dns": "_validation-persist.www.example.com", "type": "TXT", "value": "letsencrypt.org; accounturi=https://acme-staging-v02.api.letsencrypt.org/acme/acct/123456789"}
```

Follow the documentation of your DNS registrar to setup the shown DNS records
required for later verification, for each DNS record you want certificate for.

As soon as *each* record is found, the program will trigger an ACME challenge
for that dns record to actually *verify* the record contents, and so on.

The process completes once all are verified the pre-authorization.

At that time, you can copy the `account_key` to every host requiring it for
certificate renewal. Renaming the account key to hold the account number is a
good practice to track key permissions

### Step 2 (`issue`) : domain key and certificate

Running this step *on each server* allows the domain key itself to never leave
the server itself (secrets must not move).

```shell
python3 acme_tiny_dns_persistent.py issue example.com www.example.com
```

**IMPORTANT**: A domain key is created if none exists at the target
`--domain-key` location, so you can rotate your TLS server keys by simply
removing or renaming them.

On success :

- the certificate chain is printed
  - first the server certificate itself
  - then all the intermediate CA certificate, in signing order
  - as per standard practices, no root certificate is provided
- the program exits with code `0`.

```text
-----BEGIN CERTIFICATE-----
MIIGMDCCBRigAwIBAgISLAzp0S9pLtdIyNigOxQNCauYMA0GCSqGSIb3DQEBCwUA
...
+P/uOA==
-----END CERTIFICATE-----

-----BEGIN CERTIFICATE-----
MIIFETCCAvmgAwIBAgIQRWi894FoouBfrwFWfZWO7zANBgkqhkiG9w0BAQsFADBD
...
YJlfyJg=
-----END CERTIFICATE-----

-----BEGIN CERTIFICATE-----
MIIGKDCCBBCgAwIBAgIRAKYOL1Z3OCaTuowlAS/mVJgwDQYJKoZIhvcNAQELBQAw
...
jgKO5JRQNGcnvW8cVYK5AMjgRGZE6V9IxECMeEwNEFA17qGcweG1Tb3IpYs=
-----END CERTIFICATE-----
```

## About ACME "Directory URLs"

Each Certificate authority compliant with ACME protocol provides a "directory url"

Use the following option to specify the certificate provider you are using :

```shell
--acme-directory-url https://acme......
```

LetsEncrypt is the main free and public certificate authority, and is use by default

- [LetsEncrypt](https://letsencrypt.org)
  - staging/test `https://acme-staging-v02.api.letsencrypt.org/directory`
  - production `https://acme-v02.api.letsencrypt.org/directory`

Other ACME [rfc8555-compliant registries](https://datatracker.ietf.org/doc/html/rfc8555)
may follow at their own pace

- [ZeroSSL](https://zerossl.com)
  - production : `https://acme.zerossl.com/v2/DV90`

- [SSL.com](https://www.ssl.com)
  - production RSA `https://acme.ssl.com/sslcom-dv-rsa`
  - production ECC `https://acme.ssl.com/sslcom-dv-ecc`

- [Google Public
  CA](https://docs.cloud.google.com/certificate-manager/docs/public-ca)
  - staging/test `https://dv.acme-v02.test-api.pki.goog/directory`
  - production `https://dv.acme-v02.api.pki.goog/directory`
