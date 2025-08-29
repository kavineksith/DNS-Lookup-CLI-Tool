import dns.resolver
import dns.reversename
import socket
import ipaddress
import concurrent.futures
import logging
from typing import List, Dict, Tuple, Optional, Union
from dataclasses import dataclass
from datetime import datetime
import argparse

# Custom Exceptions
class DNSLookupError(Exception):
    """Base class for DNS lookup exceptions"""
    def __init__(self, message, error_code = None) -> None:
        super().__init__(message, error_code)

class InvalidDomainError(DNSLookupError):
    """Raised when an invalid domain is provided"""
    def __init__(self, message, error_code = None) -> None:
        super().__init__(message, error_code)

class InvalidIPError(DNSLookupError):
    """Raised when an invalid IP address is provided"""
    def __init__(self, message, error_code = None) -> None:
        super().__init__(message, error_code)

class DNSTimeoutError(DNSLookupError):
    """Raised when DNS query times out"""
    def __init__(self, message, error_code = None) -> None:
        super().__init__(message, error_code)

class DNSNoNameserversError(DNSLookupError):
    """Raised when no nameservers are available"""
    def __init__(self, message, error_code = None) -> None:
        super().__init__(message, error_code)

class ReverseDNSLookupError(DNSLookupError):
    """Raised when reverse DNS lookup fails"""
    def __init__(self, message, error_code = None) -> None:
        super().__init__(message, error_code)

@dataclass
class DNSRecordResult:
    domain: str
    record_type: str
    records: List[str]
    timestamp: datetime

@dataclass
class ReverseDNSResult:
    ip: str
    hostnames: List[str]
    timestamp: datetime
    method: str  # 'socket' or 'dns'

class DNSLookupClient:
    def __init__(self, timeout: int = 5, lifetime: int = 5):
        """
        Initialize DNS lookup client
        
        Args:
            timeout: Query timeout in seconds
            lifetime: Total timeout in seconds for all retries
        """
        self.timeout = timeout
        self.lifetime = lifetime
        self.logger = self._setup_logger()
        
    def _setup_logger(self) -> logging.Logger:
        """Configure and return logger instance"""
        logger = logging.getLogger('DNSLookup')
        logger.setLevel(logging.DEBUG)
        
        # Create file handler
        fh = logging.FileHandler('dns_lookup.log')
        fh.setLevel(logging.DEBUG)
        
        # Create console handler
        # ch = logging.StreamHandler()
        # ch.setLevel(logging.INFO)
        
        # Create formatter and add it to the handlers
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        fh.setFormatter(formatter)
        # ch.setFormatter(formatter)
        
        # Add the handlers to the logger
        logger.addHandler(fh)
        # logger.addHandler(ch)
        
        return logger

    def validate_domain(self, domain: str) -> bool:
        """Basic domain validation"""
        if not domain or len(domain) > 253:
            return False
        labels = domain.split('.')
        if len(labels) < 2:
            return False
        return all(label and len(label) <= 63 for label in labels)

    def validate_ip(self, ip: str) -> bool:
        """Validate IP address (both IPv4 and IPv6)"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def get_dns_records(self, domain: str, record_types: List[str]) -> Dict[str, DNSRecordResult]:
        """
        Retrieve multiple DNS records for a given domain.
        
        Args:
            domain: The domain to query
            record_types: List of DNS record types to query
        
        Returns:
            Dictionary with record types as keys and DNSRecordResult objects as values
        
        Raises:
            InvalidDomainError: If domain is invalid
            DNSLookupError: For general DNS lookup failures
        """
        if not self.validate_domain(domain):
            self.logger.error(f"Invalid domain: {domain}")
            raise InvalidDomainError(f"Invalid domain: {domain}")

        results = {}
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.lifetime
        
        # Configure resolver to use public DNS servers as fallback
        resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']
        
        self.logger.info(f"Starting DNS lookup for {domain}")

        for record_type in record_types:
            try:
                self.logger.debug(f"Querying {record_type} records for {domain}")
                
                # Skip problematic record types that might cause metaquery errors
                if record_type.upper() in ['IXFR', 'OPT', 'TKEY', 'TSIG']:
                    self.logger.debug(f"Skipping {record_type} (metaquery/problematic type)")
                    results[record_type] = DNSRecordResult(
                        domain=domain,
                        record_type=record_type,
                        records=[],
                        timestamp=datetime.now()
                    )
                    continue
                
                answers = resolver.resolve(domain, record_type)
                records = [str(r) for r in answers]
                results[record_type] = DNSRecordResult(
                    domain=domain,
                    record_type=record_type,
                    records=records,
                    timestamp=datetime.now()
                )
                self.logger.debug(f"Found {len(records)} {record_type} records for {domain}")
                
            except dns.resolver.NoAnswer:
                self.logger.debug(f"No {record_type} records found for {domain}")
                results[record_type] = DNSRecordResult(
                    domain=domain,
                    record_type=record_type,
                    records=[],
                    timestamp=datetime.now()
                )
            except dns.resolver.NXDOMAIN:
                self.logger.warning(f"Domain {domain} does not exist")
                raise DNSLookupError(f"Domain {domain} does not exist")
            except dns.resolver.NoNameservers:
                self.logger.error(f"No nameservers available for {domain}")
                raise DNSNoNameserversError(f"No nameservers available for {domain}")
            except dns.resolver.Timeout:
                self.logger.error(f"Timeout while querying {record_type} records for {domain}")
                raise DNSTimeoutError(f"Timeout while querying {domain}")
            except dns.exception.DNSException as e:
                # Handle DNS-specific exceptions more gracefully
                if "metaqueries are not allowed" in str(e).lower():
                    self.logger.warning(f"Metaquery not allowed for {record_type} on {domain}")
                    results[record_type] = DNSRecordResult(
                        domain=domain,
                        record_type=record_type,
                        records=[],
                        timestamp=datetime.now()
                    )
                else:
                    self.logger.error(f"DNS error querying {record_type} records for {domain}: {str(e)}")
                    raise DNSLookupError(f"DNS error: {str(e)}")
            except Exception as e:
                self.logger.error(f"Unexpected error querying {record_type} records for {domain}: {str(e)}")
                raise DNSLookupError(f"Unexpected error: {str(e)}")
        
        return results

    def reverse_dns_lookup_socket(self, ip: str) -> ReverseDNSResult:
        """
        Perform reverse DNS lookup using socket library.
        Works for both IPv4 and IPv6 addresses.
        
        Args:
            ip: IP address to lookup
        
        Returns:
            ReverseDNSResult object
        
        Raises:
            ReverseDNSLookupError: If reverse lookup fails
        """
        try:
            self.logger.debug(f"Performing socket reverse DNS lookup for {ip}")
            hostnames = socket.gethostbyaddr(ip)
            result = ReverseDNSResult(
                ip=ip,
                hostnames=[hostnames[0]] + list(hostnames[1]),
                timestamp=datetime.now(),
                method='socket'
            )
            self.logger.debug(f"Found {len(result.hostnames)} PTR records for {ip}")
            return result
        except (socket.herror, socket.gaierror) as e:
            self.logger.warning(f"Socket reverse DNS lookup failed for {ip}: {str(e)}")
            raise ReverseDNSLookupError(f"Socket reverse DNS lookup failed for {ip}: {str(e)}")
        except Exception as e:
            self.logger.error(f"Unexpected error during socket reverse DNS lookup for {ip}: {str(e)}")
            raise ReverseDNSLookupError(f"Unexpected error: {str(e)}")

    def reverse_dns_lookup_dns(self, ip: str) -> ReverseDNSResult:
        """
        Perform reverse DNS lookup using dnspython library.
        Works for both IPv4 and IPv6 addresses.
        
        Args:
            ip: IP address to lookup
        
        Returns:
            ReverseDNSResult object
        
        Raises:
            ReverseDNSLookupError: If reverse lookup fails
        """
        try:
            self.logger.debug(f"Performing DNS reverse lookup for {ip}")
            addr = dns.reversename.from_address(ip)
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.lifetime
            
            # Configure resolver to use public DNS servers
            resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']
            
            answers = resolver.resolve(addr, 'PTR')
            hostnames = [str(r) for r in answers]
            
            result = ReverseDNSResult(
                ip=ip,
                hostnames=hostnames,
                timestamp=datetime.now(),
                method='dns'
            )
            self.logger.debug(f"Found {len(result.hostnames)} PTR records for {ip}")
            return result
        except dns.resolver.NXDOMAIN:
            self.logger.debug(f"No PTR records found for {ip} (DNS method)")
            return ReverseDNSResult(
                ip=ip,
                hostnames=[],
                timestamp=datetime.now(),
                method='dns'
            )
        except dns.resolver.NoAnswer:
            self.logger.debug(f"No PTR records found for {ip} (DNS method)")
            return ReverseDNSResult(
                ip=ip,
                hostnames=[],
                timestamp=datetime.now(),
                method='dns'
            )
        except Exception as e:
            self.logger.error(f"DNS reverse lookup failed for {ip}: {str(e)}")
            raise ReverseDNSLookupError(f"DNS reverse lookup failed for {ip}: {str(e)}")

    def reverse_dns_lookup(self, ip: str, prefer_socket: bool = True) -> ReverseDNSResult:
        """
        Perform reverse DNS lookup with fallback mechanism.
        Tries socket method first (default), falls back to DNS method if needed.
        
        Args:
            ip: IP address to lookup
            prefer_socket: Whether to try socket method first
        
        Returns:
            ReverseDNSResult object
        
        Raises:
            InvalidIPError: If IP address is invalid
            ReverseDNSLookupError: If both methods fail
        """
        if not self.validate_ip(ip):
            self.logger.error(f"Invalid IP address: {ip}")
            raise InvalidIPError(f"Invalid IP address: {ip}")

        try:
            if prefer_socket:
                try:
                    return self.reverse_dns_lookup_socket(ip)
                except ReverseDNSLookupError:
                    self.logger.debug(f"Falling back to DNS method for {ip}")
                    return self.reverse_dns_lookup_dns(ip)
            else:
                try:
                    return self.reverse_dns_lookup_dns(ip)
                except ReverseDNSLookupError:
                    self.logger.debug(f"Falling back to socket method for {ip}")
                    return self.reverse_dns_lookup_socket(ip)
        except Exception as e:
            self.logger.error(f"All reverse DNS lookup methods failed for {ip}")
            raise ReverseDNSLookupError(f"All reverse DNS lookup methods failed for {ip}: {str(e)}")

    def bulk_reverse_lookup(self, ips: List[str], max_workers: int = 10) -> Dict[str, Union[ReverseDNSResult, str]]:
        """
        Perform reverse DNS lookups for multiple IPs in parallel.
        
        Args:
            ips: List of IP addresses to lookup
            max_workers: Maximum number of concurrent workers
        
        Returns:
            Dictionary with IPs as keys and ReverseDNSResult objects or error messages as values
        """
        results = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ip = {
                executor.submit(self.reverse_dns_lookup, ip): ip 
                for ip in ips
            }
            
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    results[ip] = future.result()
                    self.logger.info(f"Successfully completed reverse lookup for {ip}")
                except ReverseDNSLookupError as e:
                    results[ip] = f"Error: {str(e)}"
                    self.logger.error(f"Failed reverse lookup for {ip}: {str(e)}")
                except Exception as e:
                    results[ip] = f"Unexpected error: {str(e)}"
                    self.logger.error(f"Unexpected error processing {ip}: {str(e)}")
        
        return results

    def bulk_dns_lookup(
        self, 
        domains: List[str], 
        record_types: List[str], 
        max_workers: int = 10
    ) -> Dict[str, Union[Dict[str, DNSRecordResult], str]]:
        """
        Perform DNS lookups for multiple domains in parallel.
        
        Args:
            domains: List of domains to query
            record_types: List of DNS record types to query
            max_workers: Maximum number of concurrent workers
        
        Returns:
            Dictionary with domains as keys and their DNS records or error messages as values
        """
        results = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_domain = {
                executor.submit(self.get_dns_records, domain, record_types): domain 
                for domain in domains
            }
            
            for future in concurrent.futures.as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    results[domain] = future.result()
                    self.logger.info(f"Successfully completed DNS lookup for {domain}")
                except DNSLookupError as e:
                    results[domain] = f"Error: {str(e)}"
                    self.logger.error(f"Failed DNS lookup for {domain}: {str(e)}")
                except Exception as e:
                    results[domain] = f"Unexpected error: {str(e)}"
                    self.logger.error(f"Unexpected error processing {domain}: {str(e)}")
        
        return results

class DNSLookupApp:
    # Reduced to common, safe record types to avoid metaquery issues
    DEFAULT_RECORD_TYPES = [
        'A', 'AAAA', 'CNAME', 'TXT', 'NS', 'MX', 'SOA'
    ]
    
    # Extended record types for advanced users
    EXTENDED_RECORD_TYPES = [
        'A', 'AAAA', 'CNAME', 'TXT', 'SPF', 'NS', 'MX', 'SOA', 'SRV', 'PTR',
        'CAA', 'DNAME', 'DNSKEY', 'DS', 'NAPTR', 'SSHFP', 'TLSA'
    ]
    
    def __init__(self):
        self.client = DNSLookupClient()
        self.logger = self.client.logger
        
    def parse_args(self):
        """Parse command line arguments"""
        parser = argparse.ArgumentParser(description='DNS Lookup Tool')
        parser.add_argument(
            'targets',
            nargs='+',
            help='Domains or IP addresses to check (space separated)'
        )
        parser.add_argument(
            '--record-types',
            nargs='+',
            default=self.DEFAULT_RECORD_TYPES,
            help='DNS record types to check (for domain lookups). Use --extended for more types.'
        )
        parser.add_argument(
            '--extended',
            action='store_true',
            help='Use extended set of record types (may cause issues on some networks)'
        )
        parser.add_argument(
            '--timeout',
            type=int,
            default=5,
            help='DNS query timeout in seconds'
        )
        parser.add_argument(
            '--lifetime',
            type=int,
            default=5,
            help='Total DNS query lifetime in seconds'
        )
        parser.add_argument(
            '--max-workers',
            type=int,
            default=10,
            help='Maximum number of concurrent workers'
        )
        parser.add_argument(
            '--reverse-only',
            action='store_true',
            help='Only perform reverse DNS lookups (for IP targets)'
        )
        parser.add_argument(
            '--prefer-socket',
            action='store_true',
            help='Prefer socket library for reverse lookups (default)'
        )
        parser.add_argument(
            '--prefer-dns',
            action='store_true',
            help='Prefer dnspython library for reverse lookups'
        )
        parser.add_argument(
            '--use-system-dns',
            action='store_true',
            help='Use system DNS servers instead of public ones'
        )
        return parser.parse_args()

    def display_dns_results(self, dns_results: Dict[str, Union[Dict[str, DNSRecordResult], str]]):
        """Display DNS lookup results in a readable format"""
        print("\n=== DNS Lookup Results ===")
        
        for domain, records in dns_results.items():
            if isinstance(records, str):
                print(f"\nDomain: {domain}")
                print(f"  Error: {records}")
                continue
            
            print(f"\nDomain: {domain}")
            for record_type, result in records.items():
                if result.records:
                    print(f"  {record_type}:")
                    for record in result.records:
                        print(f"    - {record}")

    def display_reverse_results(self, reverse_results: Dict[str, Union[ReverseDNSResult, str]]):
        """Display reverse DNS lookup results in a readable format"""
        print("\n=== Reverse DNS Lookup Results ===")
        
        for ip, result in reverse_results.items():
            if isinstance(result, str):
                print(f"\nIP: {ip}")
                print(f"  Error: {result}")
                continue
            
            print(f"\nIP: {ip}")
            print(f"  Method: {result.method}")
            if result.hostnames:
                print("  Hostnames:")
                for hostname in result.hostnames:
                    print(f"    - {hostname}")
            else:
                print("  No PTR records found")

    def run(self):
        """Main application entry point"""
        args = self.parse_args()
        
        # Use extended record types if requested
        if args.extended and args.record_types == self.DEFAULT_RECORD_TYPES:
            args.record_types = self.EXTENDED_RECORD_TYPES
            print("Using extended record type set")
        
        self.client.timeout = args.timeout
        self.client.lifetime = args.lifetime
        
        self.logger.info("Starting DNS Lookup Application")
        self.logger.debug(f"Configuration: {vars(args)}")
        
        try:
            # Separate IPs from domains
            ips = []
            domains = []
            
            for target in args.targets:
                if self.client.validate_ip(target):
                    ips.append(target)
                elif self.client.validate_domain(target):
                    domains.append(target)
                else:
                    self.logger.warning(f"Invalid target (neither valid IP nor domain): {target}")
                    print(f"\nWarning: Invalid target '{target}' - skipping")
            
            # Handle reverse-only mode
            if args.reverse_only:
                if not ips:
                    print("\nError: No valid IP addresses provided for reverse lookup")
                    return
                
                reverse_results = self.client.bulk_reverse_lookup(
                    ips,
                    args.max_workers
                )
                self.display_reverse_results(reverse_results)
                return
            
            # Handle standard mode
            if domains:
                dns_results = self.client.bulk_dns_lookup(
                    domains,
                    args.record_types,
                    args.max_workers
                )
                self.display_dns_results(dns_results)
                
                # Perform reverse lookups for A and AAAA records
                reverse_ips = []
                for domain, records in dns_results.items():
                    if isinstance(records, dict):
                        for record_type in ['A', 'AAAA']:
                            if record_type in records:
                                reverse_ips.extend(records[record_type].records)
                
                if reverse_ips:
                    print("\n=== Reverse DNS for Domain Records ===")
                    reverse_results = self.client.bulk_reverse_lookup(
                        reverse_ips,
                        args.max_workers
                    )
                    self.display_reverse_results(reverse_results)
            
            # Handle any standalone IPs in standard mode
            if ips and not args.reverse_only:
                print("\n=== Reverse DNS for IP Targets ===")
                reverse_results = self.client.bulk_reverse_lookup(
                    ips,
                    args.max_workers
                )
                self.display_reverse_results(reverse_results)
            
        except KeyboardInterrupt:
            self.logger.info("Application interrupted by user")
            print("\nOperation cancelled by user")
        except Exception as e:
            self.logger.critical(f"Application error: {str(e)}")
            print(f"\nCritical error occurred: {str(e)}")
        finally:
            self.logger.info("DNS Lookup Application completed")

if __name__ == "__main__":
    app = DNSLookupApp()
    app.run()
