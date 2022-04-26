# DomainInvestigator :mag: #

DomainInvestigator takes in a domain or list of domains and identifies the corresponding IP(s), registrant information, country, and if a domain is potentially behind a CDN/Load Balancer.

## Getting Started ##

`DomainInvestigator` requires **3.7+**. Python 2 is not supported.

To run the tool locally from the repository, first
install the requirements:
```bash
pip install -r requirements.txt
```

### Usage and examples ###

```bash
python DomainInvestigator.py -d example.com
python DomainInvestigator.py -d example.com --enumerate_subdomains -o examplescope -f csv
python DomainInvestigator.py -d example.com --enumerate_subdomains --bruteforce -o cisascope -f json

python DomainInvestigator.py -i domains.txt -o sample_domains_output --log-level info
python DomainInvestigator.py -i domains.txt --enumerate_subdomains
```

![](./media/DomainInvestigator.gif)

![](./media/DomainInvestigator2.gif)

#### Options ####

```bash
  -h --help                              Show this message.
  --enumerate_subdomains                 Run fierce and sublist3r on input domains
  --bruteforce                           Bruteforce subdomains with sublist3r
  -d DOMAIN                              Domain to runs script against
  -o OUTPUT_FILE                         File you want to write output to
  -f OUTPUT_FILE_TYPE                    File type for output. Valid output values "csv" and "json". [default: csv]
  -i INPUT_FILE                          Load subdomains from file
  --log-level=LEVEL                      If specified, then the log level will be set to
                                         the specified value.  Valid values are "debug", "info",
                                         "warning", "error", and "critical". [default: critical]
```

## Public domain ##

This project is in the worldwide [public domain](LICENSE.md).

This project is in the public domain within the United States, and
copyright and related rights in the work worldwide are waived through
the [CC0 1.0 Universal public domain
dedication](https://creativecommons.org/publicdomain/zero/1.0/).

All contributions to this project will be released under the CC0
dedication. By submitting a pull request, you are agreeing to comply
with this waiver of copyright interest.
