import asyncio
import dns.asyncresolver
import dns.reversename
import socket
import ipaddress
import logging
from typing import List, Dict, Tuple, Optional, Union, AsyncGenerator
from dataclasses import dataclass
from datetime import datetime
import argparse

# Custom Exceptions
class DNSLookupError(Exception):
    """Base class for DNS lookup exceptions"""
    def __init__(self, message: str, error_code: Optional[int] = None) -> None:
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        
    def __str__(self) -> str:
        return f"[{self.__class__.__name__}] {self.message}"

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(message={self.message!r}, error_code={self.error_code!r})"

class InvalidDomainError(DNSLookupError):
    """Raised when an invalid domain is provided"""
    pass

class InvalidIPError(DNSLookupError):
    """Raised when an invalid IP address is provided"""
    pass

class DNSTimeoutError(DNSLookupError):
    """Raised when DNS query times out"""
    pass

class DNSNoNameserversError(DNSLookupError):
    """Raised when no nameservers are available"""
    pass

class ReverseDNSLookupError(DNSLookupError):
    """Raised when reverse DNS lookup fails"""
    pass

@dataclass
class DNSRecordResult:
    domain: str
    record_type: str
    records: List[str]
    timestamp: datetime

    def __str__(self) -> str:
        return f"{self.domain} [{self.record_type}]: {', '.join(self.records) if self.records else 'None'}"

    def __repr__(self) -> str:
        return f"DNSRecordResult(domain={self.domain!r}, record_type={self.record_type!r}, records={self.records!r}, timestamp={self.timestamp!r})"

@dataclass
class ReverseDNSResult:
    ip: str
    hostnames: List[str]
    timestamp: datetime
    method: str  # 'socket' or 'dns'

    def __str__(self) -> str:
        return f"{self.ip} (via {self.method}): {', '.join(self.hostnames) if self.hostnames else 'None'}"

    def __repr__(self) -> str:
        return f"ReverseDNSResult(ip={self.ip!r}, hostnames={self.hostnames!r}, method={self.method!r}, timestamp={self.timestamp!r})"

class DNSLookupClient:
    def __init__(self, timeout: int = 5, lifetime: int = 5, max_concurrent: int = 100):
        """
        Initialize DNS lookup client
        
        Args:
            timeout: Query timeout in seconds
            lifetime: Total timeout in seconds for all retries
            max_concurrent: Maximum concurrent async requests (Process/Memory Optimization)
        """
        self.timeout = timeout
        self.lifetime = lifetime
        self.max_concurrent = max_concurrent
        self.logger = self._setup_logger()
        self.resolver: Optional[dns.asyncresolver.Resolver] = None
        self.semaphore = asyncio.Semaphore(self.max_concurrent)
        
    def _setup_logger(self) -> logging.Logger:
        """Configure and return logger instance"""
        logger = logging.getLogger('DNSLookup')
        logger.setLevel(logging.DEBUG)
        fh = logging.FileHandler('dns_lookup.log')
        fh.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        logger.addHandler(fh)
        return logger

    # Dunder methods for Context Management (Resource optimization)
    async def __aenter__(self):
        self.logger.info("Initializing async DNS resolver context.")
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.lifetime
        self.resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.logger.info("Closing async DNS resolver context.")
        self.resolver = None

    def validate_domain(self, domain: str) -> bool:
        """Basic domain validation"""
        if self.validate_ip(domain):
            return False
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

    async def get_dns_records(self, domain: str, record_types: List[str]) -> Dict[str, DNSRecordResult]:
        """
        Retrieve multiple DNS records for a given domain asynchronously.
        """
        if not self.validate_domain(domain):
            self.logger.error(f"Invalid domain: {domain}")
            raise InvalidDomainError(f"Invalid domain: {domain}")

        if not self.resolver:
            raise RuntimeError("DNSLookupClient must be used as an async context manager.")

        results = {}
        self.logger.info(f"Starting async DNS lookup for {domain}")

        async def fetch_record(record_type: str) -> Tuple[str, DNSRecordResult]:
            async with self.semaphore:
                if record_type.upper() in ['IXFR', 'OPT', 'TKEY', 'TSIG']:
                    return record_type, DNSRecordResult(domain, record_type, [], datetime.now())
                
                try:
                    answers = await self.resolver.resolve(domain, record_type)
                    records = [str(r) for r in answers]
                    return record_type, DNSRecordResult(domain, record_type, records, datetime.now())
                except dns.resolver.NoAnswer:
                    return record_type, DNSRecordResult(domain, record_type, [], datetime.now())
                except dns.resolver.NXDOMAIN:
                    raise DNSLookupError(f"Domain {domain} does not exist")
                except dns.resolver.NoNameservers:
                    raise DNSNoNameserversError(f"No nameservers available for {domain}")
                except dns.resolver.LifetimeTimeout:
                    raise DNSTimeoutError(f"Timeout while querying {domain}")
                except dns.exception.DNSException as e:
                    if "metaqueries are not allowed" in str(e).lower():
                        return record_type, DNSRecordResult(domain, record_type, [], datetime.now())
                    raise DNSLookupError(f"DNS error: {str(e)}")
                except Exception as e:
                    raise DNSLookupError(f"Unexpected error: {str(e)}")

        tasks = [fetch_record(rt) for rt in record_types]
        gathered_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for res in gathered_results:
            if isinstance(res, Exception):
                if isinstance(res, DNSLookupError):
                    raise res
                else:
                    raise DNSLookupError(f"Unexpected error: {str(res)}")
            
            rt, record_result = res
            results[rt] = record_result
            
        return results

    async def reverse_dns_lookup_socket(self, ip: str) -> ReverseDNSResult:
        """Perform reverse DNS lookup using socket library in a non-blocking thread."""
        try:
            self.logger.debug(f"Performing socket reverse DNS lookup for {ip}")
            # gethostbyaddr is blocking, use to_thread for process optimization
            hostnames = await asyncio.to_thread(socket.gethostbyaddr, ip)
            return ReverseDNSResult(
                ip=ip,
                hostnames=[hostnames[0]] + list(hostnames[1]),
                timestamp=datetime.now(),
                method='socket'
            )
        except (socket.herror, socket.gaierror) as e:
            raise ReverseDNSLookupError(f"Socket reverse DNS lookup failed for {ip}: {str(e)}")
        except Exception as e:
            raise ReverseDNSLookupError(f"Unexpected error: {str(e)}")

    async def reverse_dns_lookup_dns(self, ip: str) -> ReverseDNSResult:
        """Perform reverse DNS lookup using dnspython async resolver."""
        try:
            self.logger.debug(f"Performing DNS reverse lookup for {ip}")
            addr = dns.reversename.from_address(ip)
            
            answers = await self.resolver.resolve(addr, 'PTR')
            hostnames = [str(r) for r in answers]
            
            return ReverseDNSResult(
                ip=ip,
                hostnames=hostnames,
                timestamp=datetime.now(),
                method='dns'
            )
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return ReverseDNSResult(ip=ip, hostnames=[], timestamp=datetime.now(), method='dns')
        except Exception as e:
            raise ReverseDNSLookupError(f"DNS reverse lookup failed for {ip}: {str(e)}")

    async def reverse_dns_lookup(self, ip: str, prefer_socket: bool = True) -> ReverseDNSResult:
        """Perform reverse DNS lookup with fallback mechanism."""
        if not self.validate_ip(ip):
            raise InvalidIPError(f"Invalid IP address: {ip}")

        async with self.semaphore:
            try:
                if prefer_socket:
                    try:
                        return await self.reverse_dns_lookup_socket(ip)
                    except ReverseDNSLookupError:
                        return await self.reverse_dns_lookup_dns(ip)
                else:
                    try:
                        return await self.reverse_dns_lookup_dns(ip)
                    except ReverseDNSLookupError:
                        return await self.reverse_dns_lookup_socket(ip)
            except Exception as e:
                raise ReverseDNSLookupError(f"All reverse DNS lookup methods failed for {ip}: {str(e)}")

    async def bulk_reverse_lookup(self, ips: List[str], prefer_socket: bool = True) -> AsyncGenerator[Tuple[str, Union[ReverseDNSResult, str]], None]:
        """
        Yields reverse DNS lookups for multiple IPs concurrently (Memory Optimization via Generator Pattern).
        """
        async def wrap_task(ip: str) -> Tuple[str, Union[ReverseDNSResult, str]]:
            try:
                res = await self.reverse_dns_lookup(ip, prefer_socket)
                return ip, res
            except Exception as e:
                return ip, str(e)
                
        wrapped_tasks = [asyncio.create_task(wrap_task(ip)) for ip in ips]
        
        for task in asyncio.as_completed(wrapped_tasks):
            ip, result = await task
            yield ip, result

    async def bulk_dns_lookup(self, domains: List[str], record_types: List[str]) -> AsyncGenerator[Tuple[str, Union[Dict[str, DNSRecordResult], str]], None]:
        """
        Yields DNS lookups for multiple domains concurrently (Memory Optimization via Generator Pattern).
        """
        async def wrap_task(domain: str) -> Tuple[str, Union[Dict[str, DNSRecordResult], str]]:
            try:
                res = await self.get_dns_records(domain, record_types)
                return domain, res
            except Exception as e:
                return domain, str(e)
                
        wrapped_tasks = [asyncio.create_task(wrap_task(domain)) for domain in domains]
        
        for task in asyncio.as_completed(wrapped_tasks):
            domain, result = await task
            yield domain, result


class DNSLookupApp:
    DEFAULT_RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'TXT', 'NS', 'MX', 'SOA']
    EXTENDED_RECORD_TYPES = DEFAULT_RECORD_TYPES + ['SPF', 'SRV', 'PTR', 'CAA', 'DNAME', 'DNSKEY', 'DS', 'NAPTR', 'SSHFP', 'TLSA']
    
    def parse_args(self):
        parser = argparse.ArgumentParser(description='DNS Lookup Tool (Async & Memory Optimized)')
        parser.add_argument('targets', nargs='+', help='Domains or IP addresses to check')
        parser.add_argument('--record-types', nargs='+', default=self.DEFAULT_RECORD_TYPES, help='DNS record types to check')
        parser.add_argument('--extended', action='store_true', help='Use extended set of record types')
        parser.add_argument('--timeout', type=int, default=5, help='DNS query timeout in seconds')
        parser.add_argument('--lifetime', type=int, default=5, help='Total DNS query lifetime in seconds')
        parser.add_argument('--max-concurrent', type=int, default=100, help='Maximum concurrent async tasks (default: 100)')
        parser.add_argument('--reverse-only', action='store_true', help='Only perform reverse DNS lookups (for IP targets)')
        parser.add_argument('--prefer-socket', action='store_true', help='Prefer socket library for reverse lookups')
        parser.add_argument('--prefer-dns', action='store_true', help='Prefer dnspython library for reverse lookups')
        return parser.parse_args()

    # Dunder method to make the app callable directly
    def __call__(self):
        """Execute the async event loop for the app"""
        try:
            asyncio.run(self.run_async())
        except KeyboardInterrupt:
            print("\nOperation cancelled by user")

    async def run_async(self):
        args = self.parse_args()
        if args.extended and args.record_types == self.DEFAULT_RECORD_TYPES:
            args.record_types = self.EXTENDED_RECORD_TYPES
            
        client = DNSLookupClient(
            timeout=args.timeout, 
            lifetime=args.lifetime, 
            max_concurrent=args.max_concurrent
        )
        
        ips = [t for t in args.targets if client.validate_ip(t)]
        domains = [t for t in args.targets if client.validate_domain(t)]
        
        invalid = set(args.targets) - set(ips) - set(domains)
        for t in invalid:
            print(f"\nWarning: Invalid target '{t}' - skipping")

        # Memory and Resource optimization using Async Context Manager
        async with client:
            if args.reverse_only:
                if not ips:
                    print("\nError: No valid IP addresses provided for reverse lookup")
                    return
                
                print("\n=== Reverse DNS Lookup Results ===")
                async for ip, result in client.bulk_reverse_lookup(ips, not args.prefer_dns):
                    self.display_reverse_result(ip, result)
                return
            
            if domains:
                print("\n=== DNS Lookup Results ===")
                reverse_ips = []
                # Using async for (generator) to stream results directly out of memory
                async for domain, result in client.bulk_dns_lookup(domains, args.record_types):
                    self.display_dns_result(domain, result)
                    if isinstance(result, dict):
                        for rt in ['A', 'AAAA']:
                            if rt in result:
                                reverse_ips.extend(result[rt].records)

                if reverse_ips:
                    print("\n=== Reverse DNS for Domain Records ===")
                    async for ip, result in client.bulk_reverse_lookup(reverse_ips, not args.prefer_dns):
                        self.display_reverse_result(ip, result)
            
            if ips and not args.reverse_only:
                print("\n=== Reverse DNS for IP Targets ===")
                async for ip, result in client.bulk_reverse_lookup(ips, not args.prefer_dns):
                    self.display_reverse_result(ip, result)

    def display_dns_result(self, domain: str, records: Union[Dict[str, DNSRecordResult], str]):
        if isinstance(records, str):
            print(f"\nDomain: {domain}\n  Error: {records}")
            return
            
        print(f"\nDomain: {domain}")
        for record_type, result in records.items():
            if result.records:
                print(f"  {record_type}:")
                for record in result.records:
                    print(f"    - {record}")

    def display_reverse_result(self, ip: str, result: Union[ReverseDNSResult, str]):
        if isinstance(result, str):
            print(f"\nIP: {ip}\n  Error: {result}")
            return
            
        print(f"\nIP: {ip}\n  Method: {result.method}")
        if result.hostnames:
            print("  Hostnames:")
            for hostname in result.hostnames:
                print(f"    - {hostname}")
        else:
            print("  No PTR records found")


if __name__ == "__main__":
    app = DNSLookupApp()
    app()
