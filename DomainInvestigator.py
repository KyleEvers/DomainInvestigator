#!/usr/bin/env python3
"""
This script runs sublist3r and fierce to enumerate subdomains, identifies the IP
and registratnt, and combines all the values for the PTP Domains csv

EXIT STATUS
    This utility exits with one of the following values:
    0   Recon completed successfully.
    >0  An error occurred.

Usage:
  DomainInvestigator (-d DOMAIN | -i INPUT_FILE)[--enumerate_subdomains [--bruteforce]][-o OUTPUT_FILE][--log-level=LEVEL][-f OUTPUT_FILE_TYPE]
  DomainInvestigator (-h | --help)

Options:
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
"""

# Standard Python Libraries
from contextlib import redirect_stdout
from dataclasses import dataclass, asdict
from io import StringIO
import json
import logging
import os
import re
import subprocess
import sys
from typing import Any, Dict, List, Set, Tuple

# Third-Party Libraries
import docopt
import dns.resolver
import dns.exception
from ipwhois import IPWhois
from IPy import IP
from schema import And, Or, Schema, SchemaError, Use
import sublist3r

# from fierce import fierce # Importing after overwriting stdout context
# manager

PRIVATE_ADDRESS: str = "Private Address"
CSV_HEADING: str = "Network,Domain,Registrant,CDN,Country"


@dataclass
class Subdomain:
    subdomain: str
    ip: str
    ips: List[str]
    registrant: str
    country: str
    cdn: bool = False

    def __post_init__(self):
        if len(self.ips) > 1:
            self.cdn = True

    def __str__(self):
        return f"{self.ip},{self.subdomain},{self.registrant},{self.cdn},{self.country}"


def run_sublister(domain: str, bruteforce: bool) -> Set[str]:
    if bruteforce:
        logging.info(
            "Running sublister with brute force mode. This may take a while.")
    sublister_subdomains = sublist3r.main(
        domain,
        40,
        f"{domain}_sublistersubdomains.txt",
        ports=None,
        silent=False,
        verbose=False,
        enable_bruteforce=bruteforce,
        engines=None,
    )
    logging.info("Sublister Complete.")
    return sublister_subdomains


def run_fierce(domain: str) -> Set[str]:
    f = StringIO()
    # Fierce prints to stdout, so we overwrite the context manger for stdout
    # to save it to a variable for processing
    with redirect_stdout(f):
        from fierce import fierce

        fierce_args = fierce.parse_args(["--domain", domain])
        # This is saving what would be printed to stdout to f
        fierce.fierce(**vars(fierce_args))

    # Get the stdout of fierce
    fierce_output = f.getvalue()
    # Regex grabs the subdomains found
    # TODO try catch for re.search
    fierce_subdomains = [
        re.search("Found: (.*). ", line).group(1)
        for line in fierce_output.splitlines()
        if "Found" in line
    ]
    logging.info(f"Fierce Complete: {fierce_subdomains}")
    return fierce_subdomains


# Given two lists of subdomains, remove duplicates
def remove_subdomain_duplicates(
    subdomains_one: Set[str], subdomains_two: Set[str]
) -> List[str]:
    all_subdomains = list(set(subdomains_one) | set(subdomains_two))
    return all_subdomains


# Given a list of domains, enumerate all subdomains and return set
def get_all_subdomains(domains: List[str], bruteforce: bool) -> Set[str]:
    results = set(domains)
    for domain in domains:
        subdomains = remove_subdomain_duplicates(
            run_sublister(domain, bruteforce), run_fierce(domain)
        )
        results = results | set(subdomains)

    return results


# Read domains in from file. Alls out of bound subdomain enumeration
def get_domains_from_file(file: str) -> List[str]:
    domains_file = open(file, "r")
    domains = domains_file.readlines()
    # Remove all newlines
    return list(map(lambda line: line.strip(), domains))


# Get list of IPs a domains A record resolves
def dns_lookup(domain: str) -> List[str]:
    dns_resolver = dns.resolver.Resolver()
    try:
        dns_answer = dns_resolver.query(domain, rdtype="A", tcp=False)
        # dns_response = [answer for answer in dns_answer.response.answer]
        ips = [ip.address for ip in dns_answer]
        return ips
    # The domain does not exist so dns resolutions remain empty
    except dns.resolver.NXDOMAIN as e:
        logging.warning(f"{e}")
    # No A record, but could be AAAA or SOA records
    except dns.resolver.NoAnswer as e:
        logging.warning(f"{e}")
    except dns.resolver.NoNameservers as e:
        logging.warning(f"{e}")
    except dns.exception.DNSException as e:
        logging.error(f"DNS exception occurred looking up {domain}: {e}")
    return []


# Run whois to get the IP, registrant, and country
def run_whois(ip: str) -> Tuple[str, str]:
    try:
        whois_response = IPWhois(ip)
        response = whois_response.lookup_whois()
        # Loop through nested responses entries and grab the Description
        # The Description is GENERALLY the Organziation/Registrant
        reg = list(entry for entry in response["nets"] if entry["description"] is not None)[
            0]["description"].replace(",", "")
        country = list(
            entry for entry in response["nets"] if entry["description"] is not None
        )[0]["country"].replace(",", "")
    # If the whois library fails us, fall back to OS whois
    except IndexError as e:
        logging.info(f"Falling back to subprocess whois: {e}")
        reg, country = fallback_whois(ip)

    return reg, country


def fallback_whois(ip: str) -> Tuple[str, str]:
    whois_response = subprocess.check_output(
        f'whois {ip} | grep -e "Organization" -e Country', shell=True
    )
    results = whois_response.splitlines()
    # TODO Change the splits to Regex
    reg = results[0].decode(
        "UTF-8").split("Organization:   ", 1)[1].replace(",", "")
    country = (
        results[1].decode("UTF-8").split("Country:        ",
                                         1)[1].replace(",", "")
    )
    return reg, country


# Given a domain return and object containing the domain, ip, ips,
# registrant and country
def get_domain_information(domain: str) -> List["Subdomain"]:
    subdomains = []
    ips = dns_lookup(domain)
    if ips:
        for ip in ips:
            # If IP is in Private range
            if IP(ip).iptype() == "PRIVATE":
                subdomain = Subdomain(domain, ip, ips, PRIVATE_ADDRESS, None)
            else:
                registrant, country = run_whois(ip)
                subdomain = Subdomain(domain, ip, ips, registrant, country)
                # time.sleep(1)
            subdomains += [subdomain]
    return subdomains


# Print results to stdout
def print_output(results: List["Subdomain"]) -> None:
    print(CSV_HEADING)
    for subdomain in results:
        print(subdomain)


# Write results to CSV file
def write_output_to_csv(results: List["Subdomain"], output: str) -> None:
    with open(f"{output}.csv", "w") as f:
        f.write(f"{CSV_HEADING}\n")
        for subdomain in results:
            f.write(f"{subdomain}\n")


# Write results to JSON
def write_output_to_json(results: List["Subdomain"], output: str) -> None:
    with open(f"{output}.json", "w") as f:
        json.dump([asdict(subdomain)
                   for subdomain in results], f, indent=4, sort_keys=True)


def main() -> None:
    args: Dict[str, str] = docopt.docopt(__doc__)
    # Validate and convert arguments as needed
    schema: Schema = Schema(
        {
            "--log-level": And(
                str,
                Use(str.lower),
                lambda n: n in ("debug", "info", "warning",
                                "error", "critical"),
                error="Possible values for --log-level are "
                + "debug, info, warning, error, and critical.",
            ),
            "-f": And(
                str,
                Use(str.lower),
                lambda n: n in ("csv", "json"),
                error="Possible values for output file type are " + "csv and json",
            ),
            "-i": Or(
                None,
                And(
                    str,
                    lambda file: os.path.isfile(file),
                    error="Input file doesn't exist!",
                ),
            ),
            "--enumerate_subdomains": bool,
            "--bruteforce": Or(False, And(True, args["--enumerate_subdomains"], error="Bruteforce requires --enumerate_subdomains option")),
            "-o": Or(None, str),
            "-d": Or(None, str),
            str: object,  # Don't care about other keys, if any
        }
    )

    try:
        validated_args: Dict[str, Any] = schema.validate(args)
    except SchemaError as err:
        # Exit because one or more of the arguments were invalid
        print(err, file=sys.stderr)
        sys.exit(1)

    # Assign validated arguments to variables
    domain: str = validated_args["-d"]
    output: str = validated_args["-o"]
    output_file_type: str = validated_args["-f"]
    input_file: str = validated_args["-i"]
    log_level: str = validated_args["--log-level"]
    enumerate_subdomains: bool = validated_args["--enumerate_subdomains"]
    bruteforce: bool = validated_args["--bruteforce"]

    # Set up logging
    logging.basicConfig(
        format="%(asctime)-15s %(levelname)s %(message)s",
        level=log_level.upper())

    if input_file:
        domains = get_domains_from_file(input_file)
    else:
        domains = [domain]

    if enumerate_subdomains:
        domains = get_all_subdomains(domains, bruteforce)

    results = []
    for domain in domains:
        results += get_domain_information(domain)

    if output:
        if output_file_type == "csv":
            write_output_to_csv(results, output)
        elif output_file_type == "json":
            write_output_to_json(results, output)
    else:
        print_output(results)

    # Stop logging and clean up
    logging.shutdown()

    # from IPython import embed; embed()


if __name__ == "__main__":
    main()
