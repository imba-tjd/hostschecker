# Hosts Checker

This tool checks whether domain matches ip in hosts file.

* It depends on server enabling HTTPS
* The hosts file must be UTF8 or UTF8-BOM

## Usage

```cmd
go install github.com/imba-tjd/hostschecker@latest
hostschecker
```

## Known results

* wsarecv: An existing connection was forcibly closed by the remote host --> SNI RST
* i/o timeout --> IP Blocked
* x509: certificate is valid for ... not ... --> IP Outdated
* x509: certificate signed by unknown authority --> Server issue, Wrong cert
