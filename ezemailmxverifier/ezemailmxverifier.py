#!/usr/bin/env python3      
# -*- coding: utf-8 -*-
from __future__ import print_function
"""Easy Email MX Verifier v1.0.0 - A complete RFC 2822 style email validation for Python."""
"""
    Author.: Ricardo Abuchaim - ricardoabuchaim@gmail.com
    License: MIT
    Github.: https://github.com/rabuchaim/ezemailmxverifier
    Issues.: https://github.com/rabuchaim/ezemailmxverifier/issues
    PyPI...: https://pypi.org/project/ezemailmxverifier/  ( pip install ezemailmxverifier )

"""
__appname__ = 'EzEmailMXVerifier'
__version__ = '1.0.0'
__release__ = '15/May/2025'

import re, socket, struct, typing, concurrent.futures, time, os, codecs
import urllib.request, urllib.error, pickle, gzip, tempfile, json, sys
import functools, math, threading, collections, itertools, email.utils
import multiprocessing

__all__ = ['EzEmailMXVerifier','EzEmailMXVerifierErrorStrings','EzEmailMXVerifierCache','EzEmailMXVerifierTopLevelDomains','safe_timeout_decorator']

class SafeTimeoutError(Exception):...
def safe_timeout_decorator(timeout: float, *, error_message="Safe timeout exceeded"):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            def target(q, *a, **k):
                try:
                    result = func(*a, **k)
                    q.put((True, result))
                except Exception as e:
                    q.put((False, e))
            q = multiprocessing.Queue()
            p = multiprocessing.Process(target=target, args=(q, *args), kwargs=kwargs)
            p.start()
            p.join(timeout)
            if p.is_alive():
                p.terminate()
                p.join()
                raise SafeTimeoutError(error_message) from None
            success, value = q.get() if not q.empty() else (False, SafeTimeoutError("Function exited unexpectedly"))
            if success:
                return value
            else:
                raise value
        return wrapper
    return decorator

class EzEmailMXVerifierTopLevelDomains(object):
    """ A modified code from publicsuffix2 package. Verify the TLD (Top Level Domain) of a domain name."""
    def __init__(self,psl_file_dir:str=os.path.dirname(__file__),auto_update_days:int=3,debug:bool=False,debug_save_dir:str=tempfile.gettempdir()):
        start_time = time.monotonic()

        if not os.path.isdir(psl_file_dir):
            raise Exception(f"Directory for public suffix list {psl_file_dir} does not exists!") from None
        if psl_file_dir is None:
            psl_file_dir = os.path.dirname(__file__)
        try:
            test_file = tempfile.TemporaryFile(dir=psl_file_dir)
            test_file.close()
        except Exception as ERR:
            raise Exception(f"Cannot access psl_file_dir ({psl_file_dir}) directory. Verify your permissions.") from None
        self.psl_file = os.path.join(psl_file_dir,'public_suffix_list.dat.gz')

        self.debug = debug
        if debug_save_dir is None:
            debug_save_dir = tempfile.gettempdir()
        if not debug: self.__debug = self.__debug_empty
        if self.debug:
            if not os.path.isdir(debug_save_dir):
                raise Exception(f"The debug_save_dir ({debug_save_dir}) does not exists!")
            self.debug_save_dir = debug_save_dir
            try:
                test_file = tempfile.TemporaryFile(dir=self.debug_save_dir)
                test_file.close()
            except Exception as ERR:
                raise Exception(f"Cannot access debug_save_dir ({self.debug_save_dir}) directory. Verify your permissions.") from None
            
        self.auto_update_days = auto_update_days if auto_update_days is not None else 0
        if self.auto_update_days == 0:
            self.__debug(f"Top Level Domains list auto update is DISABLED")
        try:
            if not os.path.isfile(self.psl_file):
                try:
                    self.fetch()
                except Exception as ERR:
                    raise Exception(f"Error fetching the public suffix list: {str(ERR)}") from None
            else:
                if self.auto_update_days > 0:
                    current_time = time.time()
                    psl_file_last_time = os.path.getmtime(self.psl_file)
                    time_diff = current_time - psl_file_last_time
                    if time_diff >= (86400*auto_update_days):
                        self.__debug(f"Public Suffix List auto-update started... the current file {self.psl_file} is older than {auto_update_days} day(s)")
                        self.fetch()
                try:
                    with gzip.GzipFile(filename=self.psl_file,mode='rb') as f:
                        self.root = pickle.load(f)
                        from pprint import pprint as pp
                except Exception as ERR:
                    try:
                        os.remove(self.psl_file)
                    except Exception as ERR:
                        self.__debug(f"Failed to remove the public suffix list file: {str(ERR)}")
                    try:
                        self.fetch()
                    except Exception as ERR:
                        raise Exception(f"Error fetching the public suffix list: {str(ERR)}") from None
            self.__debug(f'Public suffix list loaded from: {self.psl_file} [{"%.9f"%(time.monotonic()-start_time)}]')
        except Exception as ERR:
            error_message = f"Error loading the public suffix list: {str(ERR)}"
            self.__debug(error_message)
            raise Exception(error_message) from None
    def __debug_empty(self, *args):... # Empty Debug function
    def __debug(self, *args): # Debug function 
        print(f'\033[93mDEBUG: {" ".join(map(str, args))}\033[0m')
    def _build_structure(self, fp):
        root = [0]
        tlds = self.tlds
        for line in fp:
            line = line.strip()
            if not line or line.startswith('//'):
                continue
            line = line.encode('idna').decode()
            tlds.append(line)
            self._add_rule(root, line.split()[0].lstrip('.'))
        return root
    def _add_rule(self, root, rule):
        if rule.startswith('!'):
            negate = 1
            rule = rule[1:]
        else:
            negate = 0
        parts = rule.split('.')
        self._find_node(root, parts)[0] = negate
    def _simplify(self, node):
        if len(node) == 1:
            return node[0]
        return (node[0], dict((k, self._simplify(v)) for (k, v) in node[1].items()))
    def _find_node(self, parent, parts):
        if not parts:
            return parent
        if len(parent) == 1:
            parent.append({})
        assert len(parent) == 2
        _negate, children = parent
        child = parts.pop()
        child_node = children.get(child, None)
        if not child_node:
            children[child] = child_node = [0]
        return self._find_node(child_node, parts)
    def _lookup_node(self, matches, depth, parent, parts, wildcard):
        if wildcard and depth == 1:
            matches[-depth] = 0
        if parent in (0, 1):
            return
        children = parent[1]
        if depth <= len(parts) and children:
            for name in ('*', parts[-depth]):
                child = children.get(name, None)
                if child is not None:
                    if wildcard or name != '*':
                        if child in (0, 1):
                            negate = child
                        else:
                            negate = child[0]
                        matches[-depth] = negate
                        self._lookup_node(matches, depth+1, child, parts, wildcard)
    def get_tld(self,domain:str,wildcard=False,strict=True):
        if domain.find("@") != -1:
            domain = domain.split('@')[-1]
        if not domain:
            return None
        parts = domain.lower().strip('.').split('.')
        hits = [None] * len(parts)
        if strict and (self.root in (0, 1) or parts[-1] not in self.root[1].keys()):
            return None
        self._lookup_node(hits, 1, self.root, parts, wildcard)
        for i, what in enumerate(hits):
            if what is not None and what == 0:
                return '.'.join(parts[i:])
    def fetch(self, url:str='https://publicsuffix.org/list/public_suffix_list.dat', user_agent=f"{__appname__} v{__version__}", max_redirects:int=3, max_retries:int=3, timeout:float=1):
        start_time = time.monotonic()
        try:
            file_name = url.split("/")[-1]
        except Exception as ERR:
            raise Exception(f"Cannot split the URL {url} - {str(ERR)}") from None
        self.__debug(f"Downloading public suffix list from: {url}")
        for retry in range(max_retries+1):
            try:
                req = urllib.request.Request(url, headers={'User-Agent': user_agent})
                with urllib.request.urlopen(req,timeout=timeout) as response:
                    chunk_size = 4096
                    destination_path = tempfile.gettempdir()
                    destination_filename = os.path.join(destination_path,file_name)
                    try:
                        with open(destination_filename, 'wb') as output_file:
                            while True:
                                chunk = response.read(chunk_size)
                                if not chunk:
                                    break
                                output_file.write(chunk)
                    except Exception as ERR:
                        raise Exception(f"Error saving file to {destination_filename}: {str(ERR)}") from None
                    last_modified_date = response.headers.get('Last-Modified',None) if 'Last-Modified' in response.headers else None
                    self.__debug(f"Public suffix list (as text) saved to: {destination_filename} [{time.monotonic()-start_time:.5f} seconds]") 
                    
                    with codecs.open(destination_filename,'r',encoding='utf8') as psl:
                        psl = psl.readlines()
                    self.tlds = []
                    root = self._build_structure(psl)
                    self.root = self._simplify(root)
                    if self.debug:
                        try:
                            with open(destination_filename+'.json','w',encoding='utf8') as f:
                                json.dump(self.root,f,indent=3,ensure_ascii=False)
                            self.__debug(f"Public suffix list (as json) saved to: {destination_filename+'.json'}")
                        except Exception as ERR:
                            self.__debug(f"Failed to save {destination_filename}: {str(ERR)}")
                    try:
                        with gzip.GzipFile(filename=self.psl_file,mode='wb',compresslevel=9) as f:
                            pickle.dump(self.root,f,pickle.HIGHEST_PROTOCOL)
                        if last_modified_date:
                            try:
                                dt = email.utils.parsedate_to_datetime(last_modified_date)
                                ts = dt.timestamp()
                                os.utime(self.psl_file, (ts, ts))  # (atime, mtime)
                            except Exception as ERR:
                                self.__debug(f"Failed to apply Last-Modified to file {self.psl_file}: {str(ERR)}")
                        self.__debug(f"Public suffix list (pickled) saved to: {self.psl_file}")
                        return True
                    except Exception as ERR:
                        raise Exception(f"Failed to save pickled file to {destination_filename}. Verify the your permissions in directory {destination_path}: {str(ERR)}") from None
            except urllib.error.URLError as ERR:
                error_message = f"- Error downloading file: {str(ERR)} - {url}"
                if retry < max_retries:
                    if max_retries > 0:
                        timeout += 0.5
                        self.__debug(f"Retrying to download public suffix list ({retry+1}/{max_retries})... (and increasing the timeout to {timeout} seconds)")
                        time.sleep(0.5)
                        continue
                else:
                    if max_retries > 0:
                        error_message = "Exceeded maximum retries."
                        raise Exception(error_message) from None

class EzEmailMXVerifierCache(object):
    """A simple and fast cache class to store the domain and data. By ricardoabuchaim@gmail.com """
    def __init__(self):
        self.__cache = {}
        self.__stats = {'hits':0,'misses':0,'items':0,'size_in_kb':0}
        self._lock = threading.Lock()
    def get_cache(self)->dict:
        return self.__cache
    def cache_info(self):
        CacheInfo = collections.namedtuple("CacheInfo",["hits","misses","items","size_in_kb"])
        return CacheInfo(self.__stats['hits'],self.__stats['misses'],self.__stats['items'],self.__total_size(self.__cache))
    def cache_clear(self)->None:
        with self._lock:
            self.__cache.clear()
            self.__stats = {'hits':0,'misses':0,'items':0,'size_in_kb':0}        
    def add_domain(self,domain:str,data:str):
        parts = domain.split('.')
        with self._lock:
            current_level = self.__cache
            for part in reversed(parts):
                if part not in current_level:
                    current_level[part] = {}
                current_level = current_level[part]
            current_level['data'] = data
        self.__stats['items'] = self.__stats.get('items',0)+1
    def find_domain(self,domain:str)->typing.Optional[str]:
        parts = domain.split('.')
        current_level = self.__cache
        for part in reversed(parts):
            if part not in current_level:
                with self._lock:
                    self.__stats['misses'] = self.__stats.get('misses',0)+1
                return None
            current_level = current_level[part]
        return_value = current_level.get('data', None)
        with self._lock:
            self.__stats['hits'] = self.__stats.get('hits',0)+1 if return_value is not None else self.__stats['hits']
        return return_value
    def delete_domain(self,domain:str):
        parts = domain.split('.')
        with self._lock:
            current_level = self.__cache
            for part in reversed(parts):
                if part not in current_level:
                    return False
                current_level = current_level[part]
            del current_level['data']
            self.__stats['items'] = self.__stats.get('items',0)-1
        return True
    def __total_size(self,o):
        """ Returns (in KiB and with 2 decimal places) the approximate memory footprint in an object and all of its contents."""
        dict_handler = lambda d: itertools.chain.from_iterable(d.items())
        all_handlers = {tuple:iter,list:iter,str:iter,collections.deque:iter,dict:dict_handler,set:iter,frozenset:iter}
        seen = set()                 
        default_size = sys.getsizeof(0)  
        def sizeof(o):
            if id(o) in seen: return 0
            seen.add(id(o))
            s = sys.getsizeof(o, default_size)
            for typ, handler in all_handlers.items():
                if isinstance(o, typ):
                    s += sum(map(sizeof, handler(o)))
                    break
            return math.trunc((s/1024)*100)/100 # truncate the float in 2 decimal places
        with self._lock:
            return sizeof(o)
    
class EzEmailMXVerifierErrorStrings(object):
    """Error strings for the EzEmailMXVerifier class."""
    def __init__(self):
        self.error_strings = {
            "build_query_error": "Error building query for domain {domain}: {error} (query type: {query_type})",
            "dns_error": "DNS error ({error})",
            "dns_serv_fail": "DNS server failure ({error})",
            "dns_resolve_domain_exception": "Resolve domain exception for MX host {mx} of domain {domain}: {error}",
            "dns_resolve_hostname_success": "Hostname {mx} resolved to {ip_address} for domain {domain} {elapsed_time}",
            "dns_resolve_hostname_exception": "Resolve hostname exception for domain {domain}: {error} {elapsed_time}",
            "dns_verify_mx_exception": "Verify MX records exception for domain {domain}: {error}",
            "dns_verify_send_mx_query_exception": "Send Mx query exception for domain {domain}: {error}",
            "dns_verify_mx_exception_hostname": "Verify hostname ({hostname}) of MX records exception for domain {domain}: {error}",
            "dns_response_parse_error_hostname": "Error parsing DNS response for hostname {hostname} of domain {domain}: {error} (response: {response})",
            "dns_response_parse_error_mx": "Error parsing MX response for domain {domain}: {error} (response: {response})",
            "empty_domain": "Empty domain",
            "empty_email": "Empty email",
            "empty_local_part": "Empty local part",
            "invalid_domain_dns_resolve_failure": "Invalid domain (DNS resolution failed for domain {domain})",
            "invalid_domain_max_length": "Domain exceeds 253 characters",
            "invalid_domain_sintax": "Invalid domain syntax",
            "invalid_domain_sintax_dash_position": "Invalid domain syntax (Dash '-' in an invalid position)",
            "invalid_domain_sintax_dot_end": "Invalid domain syntax (Ends with a dot)",
            "invalid_domain_sintax_reason": "Invalid domain syntax (contains {reason})", 
            "invalid_email_max_length": "Email exceeds 254 characters",
            "invalid_email_sintax": "Invalid email syntax",
            "invalid_email_sintax_reason": "Invalid email syntax (contains {reason})",
            "invalid_email_sintax_exception": "Invalid email syntax exception: {error}",
            "invalid_email_sintax_missing_at": 'Invalid email syntax (missing "@")', 
            "invalid_email_sintax_more_than_one_at": 'Invalid email syntax (contain more than one "@")', 
            "invalid_local_part_contains_spaces": "Invalid local part (contains spaces)", 
            "invalid_local_part_max_length": "Invalid local part (exceeds 64 characters)",
            "invalid_tld": "Invalid top-level domain",
            "malformed_response": "Malformed response or no response records for domain {domain} (offset: {offset}, response: {response})",
            "malformed_response_incomplete": "Malformed response or incomplete for domain {domain} (offset: {offset}, response: {response})",
            "malformed_response_rdlength": "Malformed response rdlength for domain {domain} (offset: {offset}, rdlength: {rdlength}, response: {response})",
            "mx_ignore_list_type_error": "Supplied mx_ignore_list parameter discarted. Expected a list type but got: {mx_ignore_list_type}",
            "mx_ignore_list_current": "Current MX ignore list: {mx_ignore_list}",
            "mx_record_too_short": "MX record too short for domain {domain} (rdlength: {rdlength}, response: {response})",
            "mx_found_cname": "Found a CNAME ({cname}) in MX response of domain {domain}",
            "mx_unsupported_rr_type": "Skipping unsupported RR type ({rr_type}) for domain {domain} (response: {response})",
            "mx_found_empty_record": "Found an empty MX record with priority {priority} for domain {domain}",
            "mx_found_ip_address": "Found an IP address ({ip_address}) in MX record (instead a CNAME) for domain {domain}",
            "mx_found_ignore_list": "Found an MX record ({mx_record}) listed in the ignore list for domain {domain}",
            "no_authority": "No reachable authority for domain {domain}",
            "socket_error": "Socket error ({error})",
            "socket_error_for_domain": "Socket error ({error}) for domain {domain}",
            "soa_record_not_found": "SOA record not found for domain {domain} (NOERROR with empty answer)",
            "soa_response_parse_failed": "Failed to parse SOA response: {error} (response: {response})",
            "soa_record_malformed_missing_fields": "Malformed SOA record in {section_name}: missing fields",
            "soa_record_malformed_rr_header": "Malformed {section_name} RR header (offset: {offset})",
            "soa_record_not_found_in_answer": "SOA record not found in answer or authority section (response: {response})",
            "using_fallback_dns_server_domain": "Using fallback DNS server {dns_server} for domain {domain}",
            "using_fallback_dns_server_mx": "Using fallback DNS server {dns_server} for MX records of domain {domain}",
            "using_fallback_dns_server_hostname": "Using fallback DNS server {dns_server} to resolve hostname {hostname} for domain {domain}",
            "valid_domain": "Valid domain",
            "valid_email": "Valid email",
            "valid_email_sintax": "Valid email sintax",
            "valid_email_mx_ok": "Valid Email sintax with valid MX records for domain {domain}",
            "valid_email_no_mx": "Valid Email sintax but no MX records found for domain {domain}",
        }
        self.dns_rcodes = {
            0: "DNS Query completed successfully (NOERROR)",
            1: "DNS Query Format Error (FORMERR) for {domain}",
            2: "No reachable authority (SERVFAIL) for {domain}",
            3: "Domain name {domain} does not exist (NXDOMAIN)",
            4: "Function not implemented (NOTIMP)",
            5: "The server refused to answer for the query (REFUSED)",
            6: "Name that should not exist, does exist (YXDOMAIN)",
            7: "RRset that should not exist, does exist (XRRSET)",
            8: "Server not authoritative for the zone {domain} (NOTAUTH)",
            9: "Name not in zone (NOTZONE)",
            10: "DSO-TYPE Not Implemented (DSOTYPENI)",
            11: "Bad EDNS version (BADVERS)",
            16: "TSIG Signature Failure (BADSIG)",
            17: "Key not recognized (BADKEY)",
            18: "Signature out of time window (BADTIME)",
            19: "Bad TKEY Mode (BADMODE)",
            20: "Duplicate key name (BADNAME)",
            21: "Algorithm not supported (BADALG)",
            22: "Bad Truncation (BADTRUNC)",
            23: "Bad/missing Server Cookie (BADCOOKIE)",
        }
    def __call__(self,error_code:typing.Union[str,int])->str:
        """Get the error string for the given error code. If the error code is an integer, it will return DNS rcode string."""
        try:
            error_code = int(error_code)
            return self.dns_rcodes.get(error_code, "Unknown rcode error")
        except ValueError:
            return self.error_strings.get(str(error_code), "Unknown error")

    def get_dns_rcode_string(self,rcode:int)->str:
        """Get the DNS rcode string for the given rcode."""
        return self.dns_rcodes.get(rcode, "Unknown rcode error")
    def update_dns_rcode_string(self,rcode:int,error_string:str)->None:
        """Update the DNS rcode string for the given rcode."""
        self.dns_rcodes[rcode] = error_string
    def update_dns_rcodes_strings(self,dns_rcodes:dict)->None:
        """Update the DNS rcode strings for the given rcodes."""
        for rcode, error_string in dns_rcodes.items():
            self.dns_rcodes[rcode] = error_string

    def get_error_string(self,error_code:str)->str:
        """Get the error string for the given error code."""
        return self.error_strings.get(error_code, "Unknown error")
    def update_error_string(self,error_code:str,error_string:str)->None:
        """Update the error string for the given error code."""
        self.error_strings[error_code] = error_string
    def update_error_strings(self,error_strings:dict)->None:
        """Update the error strings for the given error codes."""
        for error_code, error_string in error_strings.items():
            self.error_strings[error_code] = error_string

class EzEmailMXVerifier(object):
    """
    Simple Usage:
    >>> from ezemailmxverifier import EzEmailMXVerifier
    >>> email_verifier = EzEmailMXVerifier()
    >>> response = email_verifier("ricardoabuchaim@gmail.com")
    >>> print(response)
    >>> response, error_message, mx_servers = email_verifier("ricardoabuchaim@gmail.com")
    >>> print(response, error_message, mx_servers)
    >>> for mx,priority,ips in mx_servers:
    ...   print(f"MX: {mx} - PRIORITY: {priority} - IPs: {ips}")    
    >>> response, error_message, mx_servers = email_verifier.verify_email("ricardo-abuchaim@hotmail.com")
    >>> print(f"This email is Valid? {response} - MX Servers: {mx_servers}")
    >>> response = email_verifier.verify_email("ricardoabuchaim@gmail.com",return_boolean=True)
    >>> print(response)
    >>> response, error_message = email_verifier.verify_email_sintax("ricardoabuchaim+aws1@gmail.com")
    >>> print(response, error_message)
    >>> response, error_message, mx_servers = email_verifier.verify_email("ricardoabuchaim@mailer.gmail.com")
    >>> print(response, error_message, mx_servers)
    >>> response, error_message, soa_response = email_verifier.verify_domain("ricardoabuchaim@smtp.gmail.com")
    >>> print(response, error_message)
    >>> response, error_message = email_verifier.verify_domain("smtp.gmail.com")
    >>> print(response, error_message)
    >>> response, error_message, soa_response = email_verifier.verify_domain("x.com")
    >>> import json
    >>> print(json.dumps(soa_response,indent=3))
    >>> response, error_message = email_verifier.verify_email_sintax("ricardoabuchaim@açúcar.com.br") # supports IDNs (Internationalized Domain Names)
    >>> print(response, error_message)
    """
    def __init__(self,dns_server:str="8.8.8.8",fallback_dns_server:str="1.1.1.1",timeout:float=1,timeout_max_retries:int=2,safe_timeout_enabled:bool=False,
                 mx_ignore_list:list=None,return_boolean:bool=False,
                 use_mx_cache:bool=True,use_resolver_cache:bool=True,use_soa_domain_cache:bool=True,
                 verify_tld:bool=True,tld_datfile_dest_dir:str=os.path.dirname(__file__),tld_datfile_auto_update_days:int=3,
                 debug=False,debug_flag_file_watchdog_interval:int=5,debug_flag_file_dir:str=os.path.dirname(__file__),debug_flag_file_name:str='ezemailmxverifier_debug',
                 debug_save_dir:str=tempfile.gettempdir())->None:
        """
        Initializes an instance of the email validation class using direct DNS queries.

        dns_server : str
            Primary DNS server to use for queries (default is Google "8.8.8.8")
        fallback_dns_server : str
            Secondary DNS server used as a fallback if the primary server receives a TIMEOUT (default is CloudFlare "1.1.1.1"). IS ONLY USED IF THE MAIN DNS SERVER RECEIVES A TIMEOUT.
        timeout : float
            Timeout (in seconds) for each DNS query attempt. When using the fallback server, the timeout is automatically doubled.
        timeout_max_retries : int
            Maximum number of retries in case of DNS query timeout. Use 0 to disable any extra retries (Default: 2 extra retries).
        safe_timeout_enabled : bool
            Use this function ONLY if you are experiencing long socket hangings, such as the function taking much longer than the time set in the timeout to present the timeout (considering the configured retries). Using this function can increase the elapsed time.
            A timeout decorator is applied to the __verify_mx_records/__verify_soa_domain function that will ensure that this function will never time out. 
            The timeout of this function is calculated by (timeout*4) per retry.
            This decorator uses multiprocessing to ensure that the function will never exceed the established limit, so for each execution of the __verify_mx_records/__verify_soa_domain functions a new PID is created. 
            This allows this function to work with threads (the safe_timeout made with signals only works on the main thread). 
        mx_ignore_list : list
            List of MX hostname to ignore during validation. The list in this parameter will be extended to the default list (Default: ['localhost','~','0.0.0.0']).
        return_boolean : bool
            If True, only a boolean is returned on validation; if False, detailed info is returned.
        use_mx_cache : bool
            If True, enables internal caching for MX record lookups (Default: True).
        use_resolver_cache : bool
            If True, enables caching for general DNS resolution results (Default: True).
        use_soa_domain_cache : bool
            If True, enables caching for SOA records per queried domain (Default: True).
        debug : bool
            If True, enables debug logging and writes temporary debug files for analysis (Default: False).
        debug_flag_file_watchdog_interval : int
            Interval (in seconds) to check for an external debug flag file (Default: 5). This function only works if the traditional debug parameter is set to False.
        debug_flag_file_dir : str
            Directory where the debug flag file will be monitored. Is the file ezemailmxverifier_debug exists in this directory, the debug will be enabled, otherwise the debug flag will be disabled (Default: os.path.dirname(__file__)).
        debug_save_dir : str
            Directory where cache data and cache statistics will be saved if the debug flag is enabled (Default: tempfile.gettempdir()).
        verify_tld : bool
            If True, verifies whether the domain's TLD is valid using Mozilla's official list https://publicsuffix.org/list/public_suffix_list.dat (Default: True).
        tld_datfile_dest_dir : str
            Path where the `public_suffix_list.dat.gz` file will be stored (used when verify_tld is enabled) (Default: os.path.dirname(__file__)).
        tld_datfile_auto_update_days : int
            Updates the public suffix list automatically if the current list is older than the days specified in this parameter (Default: 7 days).
        """
        self.__debug_lock = threading.Lock()
        self.__debug_flag = debug
        self.__debug_flag_file_dir = debug_flag_file_dir
        self.__debug_flag_file_name = debug_flag_file_name
        self.__debug_save_dir = debug_save_dir
        if os.getenv('ezemailmxverifier_debug',None) is not None:
            self.__debug_flag = os.getenv('ezemailmxverifier_debug',None).lower() in ['true','1','yes']
        self.__debug = self.__debug_empty if not self.__debug_flag else self.__debug_print
        ##──── this watchdog thread only works if the initial self.__debug_flag is False ─────────────────────────────────────────────────
        if debug_flag_file_watchdog_interval > 0 and not self.__debug_flag:
            threading.Thread(target=self.__worker_debug_flag_watchdog, daemon=True, args=(debug_flag_file_watchdog_interval,self.__debug_flag_file_dir,self.__debug_flag_file_name)).start()
        ##──── Use the Top Level Domain check function ───────────────────────────────────────────────────────────────────────────────────
        self.__verify_tld = verify_tld
        if self.__verify_tld:
            try:
                self.tld = EzEmailMXVerifierTopLevelDomains(psl_file_dir=tld_datfile_dest_dir,auto_update_days=tld_datfile_auto_update_days,debug=self.__debug_flag,debug_save_dir=debug_save_dir)
            except Exception as ERR:
                raise Exception(str(ERR)) from None
        ##──── self.error_string.update_error_string() or self.error_string.update_error_strings() to change the error string in runtime ─
        ##──── please, do not translate/change any error message that contains the string "timeout" ──────────────────────────────────────
        self.error_string = EzEmailMXVerifierErrorStrings()
        self.error_string.update_error_strings({"timeout": "Timeout ({timeout} seconds)"})
        self.error_string.update_error_strings({"dns_resolve_timeout_for_mx": "DNS resolve timeout for MX host {mx} of domain {domain}: {error}"})
        self.error_string.update_error_strings({"safe_timeout_reached_mx": "Safe timeout reached in verify MX records for domain {domain} {error}"})
        self.error_string.update_error_strings({"safe_timeout_reached_mx_hostname": "Safe timeout reached verifying hostname {hostname} for domain {domain} {error} {elapsed_time}"})
        self.error_string.update_error_strings({"safe_timeout_reached_send_mx_query": "Safe timeout reached when sending MX query for domain {domain} {error}" })
        ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
        self.__EMAIL_MAX_LENGTH = 254
        self.__LOCAL_PART_MAX_LENGTH = 64
        self.__DOMAIN_MAX_LENGTH = 253
        ##──── regexp from validate_email package ────────────────────────────────────────────────────────────────────────────────────────
        self.__EMAIL_VERIFY = r'^(?:(?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\((?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?(?:[\x01-\x08\x0b\x0c\x0f-\x1f\x7f\x21-\x27\x2a-\x5b\x5d-\x7e]|(?:\\.)))*(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\))*(?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\((?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?(?:[\x01-\x08\x0b\x0c\x0f-\x1f\x7f\x21-\x27\x2a-\x5b\x5d-\x7e]|(?:\\.)))*(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\)|(?:(?:[ \t]*(?:\r\n))?[ \t]+))?[\w!#$%&\'\*\+\-/=\?\^`\{\|\}~]+(?:\.[\w!#$%&\'\*\+\-/=\?\^`\{\|\}~]+)*(?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\((?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?(?:[\x01-\x08\x0b\x0c\x0f-\x1f\x7f\x21-\x27\x2a-\x5b\x5d-\x7e]|(?:\\.)))*(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\))*(?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\((?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?(?:[\x01-\x08\x0b\x0c\x0f-\x1f\x7f\x21-\x27\x2a-\x5b\x5d-\x7e]|(?:\\.)))*(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\)|(?:(?:[ \t]*(?:\r\n))?[ \t]+))?|(?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\((?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?(?:[\x01-\x08\x0b\x0c\x0f-\x1f\x7f\x21-\x27\x2a-\x5b\x5d-\x7e]|(?:\\.)))*(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\))*(?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\((?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?(?:[\x01-\x08\x0b\x0c\x0f-\x1f\x7f\x21-\x27\x2a-\x5b\x5d-\x7e]|(?:\\.)))*(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\)|(?:(?:[ \t]*(?:\r\n))?[ \t]+))?"(?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?(?:[\x01-\x08\x0b\x0c\x0f-\x1f\x7f\x21\x23-\x5b\x5d-\x7e]|(?:\\.)))*(?:(?:[ \t]*(?:\r\n))?[ \t]+)?"(?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\((?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?(?:[\x01-\x08\x0b\x0c\x0f-\x1f\x7f\x21-\x27\x2a-\x5b\x5d-\x7e]|(?:\\.)))*(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\))*(?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\((?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?(?:[\x01-\x08\x0b\x0c\x0f-\x1f\x7f\x21-\x27\x2a-\x5b\x5d-\x7e]|(?:\\.)))*(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\)|(?:(?:[ \t]*(?:\r\n))?[ \t]+))?)@(?:(?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\((?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?(?:[\x01-\x08\x0b\x0c\x0f-\x1f\x7f\x21-\x27\x2a-\x5b\x5d-\x7e]|(?:\\.)))*(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\))*(?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\((?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?(?:[\x01-\x08\x0b\x0c\x0f-\x1f\x7f\x21-\x27\x2a-\x5b\x5d-\x7e]|(?:\\.)))*(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\)|(?:(?:[ \t]*(?:\r\n))?[ \t]+))?[\w!#$%&\'\*\+\-/=\?\^`\{\|\}~]+(?:\.[\w!#$%&\'\*\+\-/=\?\^`\{\|\}~]+)*(?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\((?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?(?:[\x01-\x08\x0b\x0c\x0f-\x1f\x7f\x21-\x27\x2a-\x5b\x5d-\x7e]|(?:\\.)))*(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\))*(?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\((?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?(?:[\x01-\x08\x0b\x0c\x0f-\x1f\x7f\x21-\x27\x2a-\x5b\x5d-\x7e]|(?:\\.)))*(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\)|(?:(?:[ \t]*(?:\r\n))?[ \t]+))?|(?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\((?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?(?:[\x01-\x08\x0b\x0c\x0f-\x1f\x7f\x21-\x27\x2a-\x5b\x5d-\x7e]|(?:\\.)))*(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\))*(?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\((?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?(?:[\x01-\x08\x0b\x0c\x0f-\x1f\x7f\x21-\x27\x2a-\x5b\x5d-\x7e]|(?:\\.)))*(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\)|(?:(?:[ \t]*(?:\r\n))?[ \t]+))?\[(?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?(?:[\x01-\x08\x0b\x0c\x0f-\x1f\x7f\x21-\x5a\x5e-\x7e]|(?:\\.)))*(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\](?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\((?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?(?:[\x01-\x08\x0b\x0c\x0f-\x1f\x7f\x21-\x27\x2a-\x5b\x5d-\x7e]|(?:\\.)))*(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\))*(?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\((?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?(?:[\x01-\x08\x0b\x0c\x0f-\x1f\x7f\x21-\x27\x2a-\x5b\x5d-\x7e]|(?:\\.)))*(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\)|(?:(?:[ \t]*(?:\r\n))?[ \t]+))?)$'
        self.__VALID_EMAIL_REGEXP = re.compile(self.__EMAIL_VERIFY)
        self.__DOMAIN_VERIFY = r'^(?:(?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\((?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?(?:[\x01-\x08\x0b\x0c\x0f-\x1f\x7f\x21-\x27\x2a-\x5b\x5d-\x7e]|(?:\\.)))*(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\))*(?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\((?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?(?:[\x01-\x08\x0b\x0c\x0f-\x1f\x7f\x21-\x27\x2a-\x5b\x5d-\x7e]|(?:\\.)))*(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\)|(?:(?:[ \t]*(?:\r\n))?[ \t]+))?[\w!#$%&\'\*\+\-/=\?\^`\{\|\}~]+(?:\.[\w!#$%&\'\*\+\-/=\?\^`\{\|\}~]+)*(?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\((?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?(?:[\x01-\x08\x0b\x0c\x0f-\x1f\x7f\x21-\x27\x2a-\x5b\x5d-\x7e]|(?:\\.)))*(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\))*(?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\((?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?(?:[\x01-\x08\x0b\x0c\x0f-\x1f\x7f\x21-\x27\x2a-\x5b\x5d-\x7e]|(?:\\.)))*(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\)|(?:(?:[ \t]*(?:\r\n))?[ \t]+))?|(?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\((?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?(?:[\x01-\x08\x0b\x0c\x0f-\x1f\x7f\x21-\x27\x2a-\x5b\x5d-\x7e]|(?:\\.)))*(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\))*(?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\((?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?(?:[\x01-\x08\x0b\x0c\x0f-\x1f\x7f\x21-\x27\x2a-\x5b\x5d-\x7e]|(?:\\.)))*(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\)|(?:(?:[ \t]*(?:\r\n))?[ \t]+))?\[(?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?(?:[\x01-\x08\x0b\x0c\x0f-\x1f\x7f\x21-\x5a\x5e-\x7e]|(?:\\.)))*(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\](?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\((?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?(?:[\x01-\x08\x0b\x0c\x0f-\x1f\x7f\x21-\x27\x2a-\x5b\x5d-\x7e]|(?:\\.)))*(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\))*(?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\((?:(?:(?:[ \t]*(?:\r\n))?[ \t]+)?(?:[\x01-\x08\x0b\x0c\x0f-\x1f\x7f\x21-\x27\x2a-\x5b\x5d-\x7e]|(?:\\.)))*(?:(?:[ \t]*(?:\r\n))?[ \t]+)?\)|(?:(?:[ \t]*(?:\r\n))?[ \t]+))?)$'
        self.__VALID_DOMAIN_REGEXP = re.compile(self.__DOMAIN_VERIFY)
        ##──── for future use ────────────────────────────────────────────────────────────────────────────────────────────────────────────
        self.__BIG_PLAYERS_DOMAINS = [
            'gmail.com','outlook.com','hotmail.com','live.com','msn.com','yahoo.com','icloud.com',
            'ymail.com','rocketmail.com','me.com','mac.com','aol.com','yandex.com','yandex.ru',
            'proton.me','protonmail.com','zoho.com','gmx.com','gmx.net','mail.com','email.com','usa.com',
            'uol.com.br','terra.com.br','bol.com.br','ig.com.br','globo.com','r7.com']
        self.__BIG_PLAYERS_DOMAINS_REGEXP = re.compile(
            r"^[a-zA-Z0-9_.+-]+@("
            r"{}"
            r")$".format('|'.join(self.__BIG_PLAYERS_DOMAINS).replace('.','\.')),
            re.IGNORECASE
        )
        ##──── update the MX ignore list ─────────────────────────────────────────────────────────────────────────────────────────────────
        self.__MX_IGNORE_LIST = ['localhost','0.0.0.0','~']
        if mx_ignore_list is None:
            mx_ignore_list = []
        self.set_mx_ignore_list([*self.__MX_IGNORE_LIST,*mx_ignore_list])
        ##──── test and configure the MAIN dns server ─────────────────────────────────────────────────────────────────────────────────
        self.dns_server = dns_server
        if self.dns_server is None or dns_server == "":
            self.dns_server = "8.8.8.8"
        if self.__is_valid_ipaddr(dns_server) == False:
            raise ValueError(f"Invalid DNS server IP address: {dns_server}") from None
        self.__debug('Primary DNS server:',self.dns_server)
        ##──── test and configure the FALLBACK dns server ─────────────────────────────────────────────────────────────────────────────────
        self.fallback_dns_server = fallback_dns_server
        if self.fallback_dns_server == "":
            self.fallback_dns_server = None
        if self.fallback_dns_server is not None and self.__is_valid_ipaddr(fallback_dns_server) == False:
            raise ValueError(f"Invalid fallback DNS server IP address: {fallback_dns_server}") from None
        self.__debug('Fallback DNS server:',self.fallback_dns_server)
        ##──── Initialize the MX cache ───────────────────────────────────────────────────────────────────────────────────────────────────
        self._mx_cache = EzEmailMXVerifierCache()        
        self.use_mx_cache = use_mx_cache
        if self.use_mx_cache is None:
            self.use_mx_cache = True
        ##──── Initialize the RESOLVER cache ─────────────────────────────────────────────────────────────────────────────────────────────
        self._resolver_cache = EzEmailMXVerifierCache()        
        self.use_resolver_cache = use_resolver_cache
        if self.use_resolver_cache is None:
            self.use_resolver_cache = True
        ##──── Initialize the SOA domain cache ───────────────────────────────────────────────────────────────────────────────────────────
        self._soa_domain_cache = EzEmailMXVerifierCache()            
        self.use_soa_domain_cache = use_soa_domain_cache
        if self.use_soa_domain_cache is None:
            self.use_soa_domain_cache = True
        ##──── Starts the worker that will monitor the cache ─────────────────────────────────────────────────────────────────────────────
        threading.Thread(target=self.__worker_cache, daemon=True).start()
        ##──── Configure timeout, max retries ────────────────────────────────────────────────────────────────────────────────────────────
        self.timeout = timeout
        self.__timeout_max_retries = timeout_max_retries
        if safe_timeout_enabled:
            self.__apply_safe_timeout_decorator()
        ##──── Configure return_boolean flag ─────────────────────────────────────────────────────────────────────────────────────────────
        self.return_boolean = return_boolean
        
    def __cYellow(self,msg): return '\033[93;1m'+str(msg)+'\033[0m' # to be used in the self.__debug() function
    def __cRed(self,msg): return '\033[91;1m'+str(msg)+'\033[0m'    # to be used in the __worker_cache()
    
    def __apply_safe_timeout_decorator(self):
        """ Function to apply the secure timeout_decorator. You can override it by creating a new EzEmailMXVerifier class.
        
        Usage:
        
            class my_new_EzEmailMXVerifier(EzEmailMXVerifier):
                def __apply_safe_timeout_decorator(self):
                    # change the safe timeout to 10 times the configured timeout:
                    self.__verify_mx_records = safe_timeout_decorator(self.timeout * 10)(self.__verify_mx_records)
                    self.__verify_soa_domain = safe_timeout_decorator(self.timeout * 10)(self.__verify_soa_domain)
        """
        safe_timeout_in_seconds = self.timeout * 4
        self.__verify_mx_records = safe_timeout_decorator(safe_timeout_in_seconds)(self.__verify_mx_records)
        self.__verify_soa_domain = safe_timeout_decorator(safe_timeout_in_seconds)(self.__verify_soa_domain)
    
    def __debug(self, *args):...        # Empty Debug function 
    def __debug_empty(self, *args):...  # Empty Debug function 
    def __debug_print(self, *args):     # Debug function to print the arguments.
        """Debug function to print the arguments."""
        with self.__debug_lock:
            print(self.__cYellow(f"DEBUG: {' '.join(map(str, args))}"), flush=True)
                                    
    def __worker_debug_flag_watchdog(self,interval:int=5,debug_flag_file_dir:str=None,debug_flag_file_name:str=None)->None:
        """Watchdog to check if the debug flag file exists."""
        current_debug_flag_state = self.__debug_flag
        debug_flag_file_name = 'ezemailmxverifier_debug' if (debug_flag_file_name is None or debug_flag_file_name.strip() == '') else debug_flag_file_name
        if debug_flag_file_dir is None or (debug_flag_file_dir is not None and not os.path.isdir(debug_flag_file_dir)):
            debug_flag_file_dir = os.path.join(os.path.dirname(__file__),debug_flag_file_name)
        else:
            debug_flag_file_dir = os.path.join(debug_flag_file_dir,debug_flag_file_name)
        while True:
            try:
                if os.path.isfile(debug_flag_file_dir):
                    self.__debug_flag = True
                else:
                    self.__debug_flag = False
                if current_debug_flag_state != self.__debug_flag:
                    current_debug_flag_state = self.__debug_flag
                    if self.__debug_flag:
                        self.__debug = self.__debug_print
                        self.__debug(f"Debug flag file {debug_flag_file_name} found! Debug function set to True.")
                    else:
                        self.__debug(f"Debug flag file {debug_flag_file_name} removed! Debug function set to False.")
                        self.__debug = self.__debug_empty
            except Exception as ERR:
                self.__cRed(f"Error in EzEmailMXVerifier.__worker_debug_flag_watchdog background thread: {str(ERR)}")
            time.sleep(interval)
        
    def __worker_cache(self,interval:int=10):
        """Worker to run in background to show and save all cache information when running in debug mode"""
        self.__debug(self.__cRed(f"Running background thread to monitor the application cache each {interval} seconds..."))
        while True:
            try:
                time.sleep(interval)
                if (self.use_mx_cache == False and self.use_resolver_cache == False and self.use_soa_domain_cache == False) or (not self.__debug_flag):
                    continue
                statistics = {}
                if self.use_mx_cache == True:
                    mx_cache_stats = self._mx_cache.cache_info()
                    mx_cache_stats = {'hits':mx_cache_stats.hits,'misses':mx_cache_stats.misses,'items':mx_cache_stats.items,'size_in_kb':mx_cache_stats.size_in_kb}
                    statistics['mx_cache'] = mx_cache_stats
                    mx_cache_save_path = os.path.join(self.__debug_save_dir,'EzEmailMXVerifier-mx_cache.json')
                    self.__debug(self.__cRed(f"MX CACHE: {mx_cache_stats} (saved to {mx_cache_save_path})"))
                    with open(mx_cache_save_path, 'w') as f:
                        json.dump(self._mx_cache.get_cache(), f, indent=3, sort_keys=False)
                if self.use_resolver_cache == True:
                    resolver_cache_stats = self._resolver_cache.cache_info()
                    resolver_cache_stats = {'hits':resolver_cache_stats.hits,'misses':resolver_cache_stats.misses,'items':resolver_cache_stats.items,'size_in_kb':resolver_cache_stats.size_in_kb}
                    statistics['resolver_cache'] = resolver_cache_stats
                    resolver_cache_save_path = os.path.join(self.__debug_save_dir,'EzEmailMXVerifier-resolver_cache.json')
                    self.__debug(self.__cRed(f"RESOLVER CACHE: {resolver_cache_stats} (saved to {resolver_cache_save_path})"))
                    with open(resolver_cache_save_path, 'w') as f:
                        json.dump(self._resolver_cache.get_cache(), f, indent=3, sort_keys=False)
                if self.use_soa_domain_cache == True:
                    soa_domain_stats = self._soa_domain_cache.cache_info()
                    soa_domain_stats = {'hits':soa_domain_stats.hits,'misses':soa_domain_stats.misses,'items':soa_domain_stats.items,'size_in_kb':soa_domain_stats.size_in_kb}
                    statistics['soa_domain_cache'] = soa_domain_stats
                    soa_domain_cache_save_path = os.path.join(self.__debug_save_dir,'EzEmailMXVerifier-soa_domain_cache.json')
                    self.__debug(self.__cRed(f"SOA DOMAIN CACHE: {soa_domain_stats} (saved to {soa_domain_cache_save_path})"))
                    with open(soa_domain_cache_save_path, 'w') as f:
                        json.dump(self._soa_domain_cache.get_cache(), f, indent=3, sort_keys=False)
                self.__debug(self.__cRed(f"STATISTICS: (saved to /tmp/EzEmailMXVerifier-statistics.json)"))
                with open('/tmp/EzEmailMXVerifier-statistics.json', 'w') as f:
                    json.dump(statistics, f, indent=3, sort_keys=False)
            except Exception as ERR:
                self.__debug(self.__cRed(f"Error in __worker_cache background thread: {str(ERR)}"))
                time.sleep(interval)
                
    def __is_valid_ipaddr(self,ipaddr:str)->bool:
        """This is the fastest way to check if an IP address is valid, convert it to a 32-bit integer and check if it is valid."""
        try:
            int(struct.unpack("!L", socket.inet_aton(ipaddr))[0])
            return True
        except Exception as ERR:
            # self.__debug(f"Invalid IP address: {ipaddr} ({ERR})")
            return False
        
    def get_mx_ignore_list(self)->list: 
        """Get the current MX ignore list."""
        return self.__MX_IGNORE_LIST
    def set_mx_ignore_list(self,mx_ignore_list:list)->bool:
        """Set the MX ignore list."""
        if mx_ignore_list is not None and isinstance(mx_ignore_list, list):
            self.__MX_IGNORE_LIST = list(set(mx_ignore_list))
        elif mx_ignore_list is not None:
            self.__debug(self.error_string('mx_ignore_list_type_error').format(mx_ignore_list_type=type(mx_ignore_list)))
            return False
        self.__debug(self.error_string('mx_ignore_list_current').format(mx_ignore_list=self.__MX_IGNORE_LIST))
        return True
        
    def __call__(self,email:str,return_boolean:bool=None)->typing.Tuple[bool,str,typing.List[str]]:
        """Check if the email is valid and if the domain and MX records are valid. This function is the same as self.verify_email()
        
        return_boolean: If True, return a boolean value. If False, return a tuple with the result (boolean) and the error message (string) and MX records.
        
        Usage: 
        
            emailvalidator = EzEmailMXVerifier()
            result,error_message,mx_records = emailvalidator('myemail@mydomain.com')
            print(result,error_message,mx_records)
            result = emailvalidator('myemail@mydomain.com',return_boolean=True)
            print(result)
        """
        if return_boolean is None:
            return_boolean = self.return_boolean
        return self.verify_email(email,return_boolean=return_boolean)
       
    def verify_email_sintax(self,email:str,return_boolean=None)->typing.Tuple[bool,str]:
        """Check ONLY if the email sintax is valid. Does not check if the domain is valid or if the MX records are valid.
        
        return_boolean: If True, return a boolean value. If False, return a tuple with the result (boolean) and the error message (string).
     
        Usage: 
        
            emailvalidator = EzEmailMXVerifier()
            result,error_message = emailvalidator.verify_email_sintax('myemail@mydomain.com')
            print(result,error_message)
            result = emailvalidator.verify_email_sintax('myemail@mydomain.com',return_boolean=True)
            print(result)        
        """
        if return_boolean is None:
            return_boolean = self.return_boolean
        result = True, self.error_string('valid_email_sintax')
        if not email:
            result = False, self.error_string('empty_email')
        elif len(str(email)) > self.__EMAIL_MAX_LENGTH:
            result = False, self.error_string('invalid_email_max_length')
        else:
            try:
                LOCAL_PART, DOMAIN = email.split('@')
                if len(LOCAL_PART) == 0:
                    result = False, self.error_string('empty_local_part')
                elif LOCAL_PART.find(" ") != -1:
                    result = False, self.error_string('invalid_email_sintax_reason').format(reason='spaces')
                elif LOCAL_PART.find(",") != -1:
                    result = False, self.error_string('invalid_email_sintax_reason').format(reason='","')
                elif LOCAL_PART.find("..") != -1:
                    result = False, self.error_string('invalid_email_sintax_reason').format(reason='".."')
                elif len(LOCAL_PART) > self.__LOCAL_PART_MAX_LENGTH:
                    result = False, self.error_string('invalid_local_part_max_length')
                elif len(DOMAIN) == 0:
                    result = False, self.error_string('empty_domain')
                elif len(DOMAIN) > self.__DOMAIN_MAX_LENGTH:
                    result = False, self.error_string('invalid_domain_max_length')
                else:
                    domain_result, domain_error_message = self.verify_domain_sintax(DOMAIN,return_boolean=False)
                    if domain_result == False:
                        result = False, domain_error_message
            except Exception as ERR:
                if str(ERR).lower().find("not enough values to unpack") != -1:
                    result = False, self.error_string('invalid_email_sintax_missing_at')
                elif str(ERR).lower().find("too many values to unpack") != -1:
                    result = False, self.error_string('invalid_email_sintax_more_than_one_at')
                else:
                    result = False, self.error_string('invalid_email_sintax_exception').format(reason=str(ERR))
        if result[0] == True:
            if not self.__VALID_EMAIL_REGEXP.match(str(email)):
                result = False, self.error_string('invalid_email_sintax')
        if return_boolean:
            return result[0] 
        return result
                   
    def verify_email(self,email:str,return_boolean=None)->typing.Tuple[bool,str,typing.List[str]]:
        """Check if the email is valid and if the domain and MX records are valid.
        
        return_boolean: If True, return a boolean value. If False, return a tuple with the result (boolean) and the error message (string).
        
        Usage: 
        
            emailvalidator = EzEmailMXVerifier()
            result,error_message,mx_records = emailvalidator.verify_email('myemail@mydomain.com')
            # mx_records is a list of tuples containing the MX server hostname, priority, and IPs of that MX server
            print(result,error_message,mx_records)
            result = emailvalidator.verify_email('myemail@mydomain.com',return_boolean=True)
            print(result)                
        """
        try:
            self.__debug('Verifying email:',email)
            if return_boolean is None:
                return_boolean = self.return_boolean
            try:
                valid_email_sintax = self.verify_email_sintax(email,return_boolean=return_boolean)
            except Exception as ERR:
                if return_boolean:
                    return False
                valid_email_sintax = False, str(ERR), []
            if (return_boolean and valid_email_sintax == False) or (not return_boolean and valid_email_sintax[0] == False):
                if return_boolean:
                    return False
                return False, valid_email_sintax[1], []
            mx_records = []
            if (return_boolean and valid_email_sintax == True) or (not return_boolean and valid_email_sintax[0] == True):
                result = False
                retry = 0
                local_part, domain = email.split('@')
                while retry <= self.__timeout_max_retries:
                    try:
                        result, error_message, mx_records = self.__verify_mx_records(domain)
                    except Exception as ERR:
                        error_message = str(ERR)
                    if result == True:
                        break
                    if error_message.lower().find("timeout") == -1 and len(error_message) > 14:
                        break
                    retry += 1
                    if retry <= self.__timeout_max_retries:
                        self.__debug(f"Retry {retry}/{self.__timeout_max_retries} for email {email}...")
                if return_boolean:
                    return result
                return result, error_message, mx_records
            if return_boolean:
                return result
            return result, valid_email_sintax[1], mx_records
        except Exception as ERR:
            self.__debug(f"Error in verify email function: {str(ERR)}")
                
    def verify_domain_sintax(self,domain:str,return_boolean:bool=None)->typing.Tuple[bool,str]:
        """Check ONLY if the domain sintax is valid. Does not check if the domain is valid or if the MX records are valid.
        
        return_boolean: If True, return a boolean value. If False, return a tuple with the result (boolean) and the error message (string).
        
        Usage:

            emailvalidator = EzEmailMXVerifier()
            result,error_message = emailvalidator.verify_domain_sintax('mydomain.com')
            print(result,error_message)
            result = emailvalidator.verify_domain_sintax('mydomain.com',return_boolean=True)
            print(result)                
        """
        self.__debug('Verifying domain sintax:',domain)
        if return_boolean is None:
            return_boolean = self.return_boolean
        domain = str(domain).lower().strip()
        result = True, self.error_string('valid_domain')
        if domain in ['none','']:
            result = False, self.error_string('empty_domain')
        elif len(str(domain)) > self.__DOMAIN_MAX_LENGTH:
            result = False, self.error_string('invalid_domain_max_length')
        elif domain.find("@") != -1:
            result = False, self.error_string('invalid_domain_sintax_reason').format(reason='"@"')
        elif domain.find(" ") != -1:
            result = False, self.error_string('invalid_domain_sintax_reason').format(reason='spaces')
        elif domain.find("..") != -1:
            result = False, self.error_string('invalid_domain_sintax_reason').format(reason='".."')
        elif domain.find(",") != -1:
            result = False, self.error_string('invalid_domain_sintax_reason').format(reason='","')
        elif domain[-1] == ".":
            result = False, self.error_string('invalid_domain_sintax_dot_end')
        elif domain.find("-.") != -1 or domain.find(".-") != -1 or domain[0] == "-" or domain[-1] == "-":
            result = False, self.error_string('invalid_domain_sintax_dash_position')
        else:
            if self.__verify_tld:
                if self.tld.get_tld(domain) is None:
                    result = False, self.error_string('invalid_tld')
            else:
                try:
                    if not self.__VALID_DOMAIN_REGEXP.match(str(domain)):
                        result = False, self.error_string('invalid_domain_sintax')
                except ValueError:
                    result = False, self.error_string('invalid_domain_sintax')
        if return_boolean:
            return result[0]
        return result
                        
    def verify_domain(self,domain:str,return_boolean:bool=None)->typing.Tuple[bool,str,dict]:
        """Check ONLY if the domain is valid. Does not check if the MX records are valid.
        
        return_boolean: If True, return a boolean value. If False, return a tuple with the result (boolean), the error message (string) and (if True) the soa_response records (dict).
        
        Usage:

            emailvalidator = EzEmailMXVerifier()
            result,error_message,soa_response = emailvalidator.verify_domain('mydomain.com')
            # soa_response is a dict
            print(result,error_message,soa_response)
            result = emailvalidator.verify_domain('mydomain.com',return_boolean=True)
            print(result)
        """
        self.__debug('Verifying SOA response for domain:',domain)
        if return_boolean is None:
            return_boolean = self.return_boolean
        domain = str(domain).lower().strip()            
        if self.use_soa_domain_cache == True:
            start_time = time.monotonic()
            cached_response = self._soa_domain_cache.find_domain(domain)
            if cached_response is not None:
                self.__debug(f">>> Found in cache SOA records for domain {domain} [{'%.9f'%(time.monotonic()-start_time)}]: {cached_response}")
                if return_boolean:  
                    return True
                return True, self.error_string('valid_domain'), cached_response
        sintax_result, sintax_error_message = self.verify_domain_sintax(domain,return_boolean=False)
        result = sintax_result, sintax_error_message, {}
        if sintax_result:
            timed_out = False
            retry = 0
            with concurrent.futures.ThreadPoolExecutor() as executor:
                while retry <= self.__timeout_max_retries:
                    future = executor.submit(self.__verify_soa_domain, domain, self.dns_server, self.timeout)
                    try:
                        response, response_error_message, soa_response = future.result(timeout=self.timeout)
                        result = response, response_error_message, soa_response
                        if str(soa_response).lower().find("soa record not found") != -1:
                            result = False, self.error_string('soa_record_not_found').format(domain), {}
                    except concurrent.futures.TimeoutError as ERR:
                        result = False, self.error_string('timeout').format(timeout=self.timeout), {}
                        timed_out = True
                    except Exception as ERR:
                        result = False, self.error_string('invalid_domain_dns_resolve_failure').format(domain=domain), {}
                    if timed_out == True or result[1].lower().find("timeout") != -1:
                        if self.fallback_dns_server is not None:
                            self.__debug(self.error_string('using_fallback_dns_server_domain').format(dns_server=self.fallback_dns_server,domain=domain))
                            future = executor.submit(self.__verify_soa_domain, domain, self.fallback_dns_server, self.timeout*2)
                            try:
                                response, response_error_message, soa_response = future.result(timeout=self.timeout*2)
                                result = response, response_error_message, soa_response
                            except concurrent.futures.TimeoutError as ERR:
                                result = False, self.error_string('timeout').format(timeout=(self.timeout*2)+self.timeout), {}
                            except Exception as ERR:
                                result = False, self.error_string('invalid_domain_dns_resolve_failure').format(domain=domain), {}
                    if result[1].lower().find("timeout") != -1:
                        retry += 1
                        if retry <= self.__timeout_max_retries:
                            self.__debug(f"Retry {retry}/{self.__timeout_max_retries} for domain {domain}")
                    else:
                        break
                    
            if result[0] == True and self.use_soa_domain_cache == True:
                start_time = time.monotonic()
                self._soa_domain_cache.add_domain(domain, result[2])
                self.__debug(f">>> Added to cache SOA records for domain {domain} [{'%.9f'%(time.monotonic()-start_time)}]")
                # cache validation
                # assert self._soa_domain_cache.find_domain(domain) == result[2]
        if return_boolean:
            return result[0] 
        return result
    
    def __build_query(self,domain:str,query_type:int)->bytes:
        """Build the DNS query to send to the DNS server"""
        try:
            packet_id = 1
            flags = 0x0100  # Consulta padrão
            questions = 1
            answer_rrs = 0
            authority_rrs = 0
            additional_rrs = 0
            query = struct.pack(">HHHHHH", packet_id, flags, questions, answer_rrs, authority_rrs, additional_rrs)
            domain = domain.encode('idna').decode()
            for part in domain.split("."):
                query += struct.pack("B", len(part))+part.encode("utf-8")
            query += b'\x00'  # Fim do nome do domínio
            query += struct.pack(">HH", query_type, 1)  # Tipo da consulta e classe IN
            return query
        except Exception as ERR:
            self.__debug(self.error_string('build_query_error').format(domain=domain,error=str(ERR),query_type=query_type))
            return b''

    def __verify_soa_domain(self,domain:str,dns_server:str,timeout:float)->bool:
        """Check if a domain exists by querying its SOA record."""
        query = self.__build_query(domain, 6)  # SOA
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(query, (dns_server, 53))
            response, _ = sock.recvfrom(512)
            flags = struct.unpack(">H", response[2:4])[0]
            rcode = flags & 0x000F
            if rcode != 0:
                error_message = self.error_string(rcode).format(domain=domain)
                return False, error_message, {}
            else:
                soa_response = self.__parse_soa_response(response,domain,rcode)
                if soa_response['error_message'].lower().find("soa record not found") != -1:
                    return False, self.error_string('soa_record_not_found').format(domain=domain), {}
                elif soa_response['error_message'] != '':
                    return False, soa_response['error_message'], {}
                answer_count = struct.unpack(">H", response[6:8])[0]
            return answer_count >= 0, self.error_string('valid_domain'), soa_response
        except socket.timeout:
            return False, self.error_string('timeout').format(timeout=sock.timeout), {}
        except socket.gaierror as ERR:
            return False, self.error_string('socket_error').format(error=str(ERR)), {}
        except Exception as ERR:
            return False, self.error_string('dns_serv_fail').format(error=str(ERR)), {}
        finally:
            sock.close()
                
    def __parse_soa_response(self,response:bytes,domain:str,rcode:int)->dict:
        """Parse the SOA response and return the relevant information."""
        def parse_rr(offset, section_name):
            if offset + 10 > len(response):
                return None, self.error_string('soa_record_malformed_rr_header').format(section_name=section_name,offset=offset)
            rr_name, offset = self.__parse_domain_name(response, offset)
            rr_type = int.from_bytes(response[offset:offset+2], 'big')
            offset += 8  # pula type, class, ttl
            rdlength = int.from_bytes(response[offset:offset+2], 'big')
            offset += 2
            if rr_type == 6:  # SOA
                rdata_end = offset + rdlength
                mname, offset = self.__parse_domain_name(response, offset)
                rname, offset = self.__parse_domain_name(response, offset)
                if offset + 20 > len(response):
                    return None, self.error_string('soa_record_malformed_missing_fields').format(section_name=section_name)
                serial = int.from_bytes(response[offset:offset+4], 'big')
                refresh = int.from_bytes(response[offset+4:offset+8], 'big')
                retry = int.from_bytes(response[offset+8:offset+12], 'big')
                expire = int.from_bytes(response[offset+12:offset+16], 'big')
                minimum = int.from_bytes(response[offset+16:offset+20], 'big')
                return {'name': rr_name,'mname': mname,'rname': rname,'serial': serial,'refresh': refresh,
                        'retry': retry,'expire': expire,'minimum': minimum,'error_message': ''}, None
            offset += rdlength
            return None, offset
        
        error_message = self.error_string(rcode).format(domain=domain)
        return_package = {'name':'','mname':'','rname':'','serial':0,'refresh':0,'retry':0,'expire':0,'minimum':0,'error_message':error_message}
        try:
            answer_count = int.from_bytes(response[6:8], 'big')
            authority_count = int.from_bytes(response[8:10], 'big')
            name, offset = self.__parse_domain_name(response, 12)
            return_package['name'] = name
            offset += 4  # pula tipo + classe
            # 1. Tenta parsear os registros da Answer Section
            for _ in range(answer_count):
                rr_result, result_or_err = parse_rr(offset, 'answer')
                if isinstance(rr_result, dict):
                    return rr_result
                elif isinstance(result_or_err, str):
                    return_package['error_message'] = result_or_err
                    return return_package
                else:
                    offset = result_or_err
            # 2. Se não encontrou SOA na resposta, tenta na Authority Section
            for _ in range(authority_count):
                rr_result, result_or_err = parse_rr(offset, 'authority')
                if isinstance(rr_result, dict):
                    return rr_result
                elif isinstance(result_or_err, str):
                    return_package['error_message'] = result_or_err
                    return return_package
                else:
                    offset = result_or_err
            return_package['error_message'] = self.error_string('soa_record_not_found_in_answer').format(response=response)
            return return_package
        except Exception as ERR:
            return_package['error_message'] = self.error_string('soa_response_parse_failed').format(error=str(ERR),response=response)
            return return_package
        
    def __parse_domain_name(self, response: bytes, idx: int):
        """Parse the domain name from a DNS response"""
        labels = []
        jumped = False
        original_idx = idx
        while True:
            length = response[idx]
            if length == 0:
                idx += 1
                break
            elif (length & 0xC0) == 0xC0:  # Ponteiro
                if not jumped:
                    original_idx = idx+2
                pointer = ((length & 0x3F) << 8) | response[idx+1]
                pointed_name, _ = self.__parse_domain_name(response, pointer)
                labels.append(pointed_name)
                idx += 2
                jumped = True
                break
            else:
                idx += 1
                labels.append(response[idx:idx+length].decode())
                idx += length
        if not jumped:
            return ".".join(labels), idx
        else:
            return ".".join(labels), original_idx
    
    def __verify_mx_records(self,domain:str)->typing.Tuple[bool,typing.List[str]]:
        """Check if the domain has MX records."""
        domain = str(domain).lower().strip()
        if self.use_mx_cache:
            start_time = time.monotonic()
            mx_servers = self._mx_cache.find_domain(domain)
            if mx_servers is not None:
                self.__debug(f">>> Found in cache MX servers for domain {domain} [{'%.9f'%(time.monotonic()-start_time)}]: {mx_servers}")
                if len(mx_servers) > 0:
                    return True, self.error_string('valid_email_mx_ok').format(domain=domain), mx_servers
                else:
                    return False, self.error_string('valid_email_no_mx').format(domain=domain), []
        try:
            response_result, mx_records = self.__send_mx_query(domain,self.dns_server,self.timeout)
            if isinstance(mx_records,str):
                result = False, mx_records, []
            elif isinstance(mx_records,list):
                if len(mx_records) == 0:
                    return False, self.error_string('valid_email_no_mx').format(domain=domain), []
                result = response_result, self.error_string('valid_email_mx_ok').format(domain=domain), mx_records
            if result[1].lower().find("timeout") != -1:
                if self.fallback_dns_server is not None:
                    self.__debug(self.error_string('using_fallback_dns_server_mx').format(dns_server=self.fallback_dns_server,domain=domain))
                    response_result, mx_records = self.__send_mx_query(domain,self.fallback_dns_server,self.timeout*2)
                    if isinstance(mx_records,str):
                        result = False, mx_records, []
                    elif isinstance(mx_records,list):
                        if len(mx_records) == 0:
                            return False, self.error_string('valid_email_no_mx').format(domain=domain), []
                        result = response_result, self.error_string('valid_email_mx_ok').format(domain=domain), mx_records
                    if result[1].lower().find("timeout") != -1:
                        result = False, self.error_string('timeout').format(timeout=(self.timeout*2)+self.timeout), []
            if result[0] == False:
                return result
        except Exception as ERR:
            if str(ERR).lower().find('safe timeout') != -1:
                error_message = self.error_string('safe_timeout_reached_send_mx_query').format(domain=domain,error=str(ERR))
                self.__debug(error_message)
                return False, error_message, []
            return False, self.error_string('dns_verify_send_mx_query_exception').format(domain=domain,error=str(ERR)), []
        try:            
            valid_mx_servers = []
            with concurrent.futures.ThreadPoolExecutor(10) as executor:
                for mx, priority in mx_records:
                    mx = mx.lower()
                    if self.use_resolver_cache:
                        start_time = time.monotonic()
                        ips_response = self._resolver_cache.find_domain(mx)
                        if ips_response is not None:
                            self.__debug(f">>> Found in cache the hostname {mx} [{'%.9f'%(time.monotonic()-start_time)}]: {ips_response} for domain {domain}")
                            valid_mx_servers.append((mx,priority,ips_response))
                            continue
                    try:
                        start_time = time.monotonic()
                        future = executor.submit(self.__resolve_hostname, mx, domain)
                        try:
                            response_host_domain, response_ipaddr_or_err = future.result(timeout=self.timeout*2)
                            if response_host_domain == True and isinstance(response_ipaddr_or_err,list) and len(response_ipaddr_or_err) > 0:
                                self.__debug(self.error_string('dns_resolve_hostname_success').format(mx=mx,ip_address=response_ipaddr_or_err,domain=domain,elapsed_time=f"[{'%.9f'%(time.monotonic()-start_time)}]"))
                                valid_mx_servers.append((mx,priority,response_ipaddr_or_err))
                                if self.use_resolver_cache:
                                    start_time = time.monotonic()
                                    self._resolver_cache.add_domain(mx,response_ipaddr_or_err)
                                    self.__debug(f">>> Added to resolver cache the IPs for hostname {mx} [{'%.9f'%(time.monotonic()-start_time)}]")
                            else:
                                self.__debug(self.error_string('dns_resolve_hostname_exception').format(mx=mx,domain=domain,error=response_ipaddr_or_err,elapsed_time=f"[{'%.9f'%(time.monotonic()-start_time)}]"))
                        except concurrent.futures.TimeoutError as ERR:
                            error_message = self.error_string('dns_resolve_timeout_for_mx').format(mx=mx,domain=domain,error=str(ERR),elapsed_time=f"[{'%.9f'%(time.monotonic()-start_time)}]")
                            self.__debug(error_message)
                            return False, error_message, []
                        except Exception as ERR:
                            if str(ERR).lower().find('safe timeout') != -1:
                                self.__debug(self.error_string('safe_timeout_reached_mx_hostname').format(hostname=mx,domain=domain,error=str(ERR),elapsed_time=f"[{'%.9f'%(time.monotonic()-start_time)}]"))
                                if len(valid_mx_servers) > 0:
                                    return True, self.error_string('valid_email_mx_ok').format(domain=domain), valid_mx_servers
                                else:
                                    return False, self.error_string('safe_timeout_reached_mx_hostname').format(hostname=mx,domain=domain,error=str(ERR),elapsed_time=f"[{'%.9f'%(time.monotonic()-start_time)}]"), []
                            error_message = self.error_string('dns_resolve_domain_exception').format(mx=mx,domain=domain,error=str(ERR))
                            self.__debug(error_message)
                            return False, error_message, []
                    except Exception as ERR:
                        error_message = self.error_string('dns_verify_mx_exception_hostname').format(hostname=mx,domain=domain,error=str(ERR))
                        self.__debug(error_message)
                        return False, error_message, []
            if self.use_mx_cache and len(valid_mx_servers) > 0:
                start_time = time.monotonic()
                self._mx_cache.add_domain(domain,valid_mx_servers)
                self.__debug(f">>> Added to cache MX records for domain {domain} [{'%.9f'%(time.monotonic()-start_time)}]")
            if len(valid_mx_servers) == 0:
                return False, self.error_string('valid_email_no_mx').format(domain=domain), []
            return True, self.error_string('valid_email_mx_ok').format(domain=domain), valid_mx_servers
        except Exception as ERR:
            if str(ERR).lower().find('safe timeout') != -1:
                error_message = self.error_string('safe_timeout_reached_mx').format(domain=domain,error=str(ERR))
                self.__debug(error_message)
                if len(valid_mx_servers) > 0:
                    return True, self.error_string('valid_email_mx_ok').format(domain=domain), valid_mx_servers 
                return False, error_message, []
            error_message = self.error_string('dns_verify_mx_exception').format(domain=domain,error=str(ERR))
            self.__debug(error_message)
            return False, error_message, []
                
    def __send_mx_query(self,domain:str,dns_server:str,timeout:float)->typing.Tuple[bool,typing.Union[bytes,str]]:
        """Send que DNS query directly to the DNS server"""
        try:
            query = self.__build_query(domain, 15) # MX Records
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(query, (dns_server, 53))
            response, _ = sock.recvfrom(512)
            flags = struct.unpack(">H", response[2:4])[0]
            rcode = flags & 0x000F
            if rcode != 0:
                result = False, self.error_string(rcode).format(domain=domain)
            else:
                answer_count = struct.unpack(">H", response[6:8])[0]
                if answer_count == 0:
                    result = False, []
                else:
                    mx_records = self.__parse_mx_response(domain,response)
                    if len(mx_records) == 0:
                        result = False, []
                    else:
                        result = True, mx_records
            return result
        except socket.timeout as ERR:
            return False, self.error_string('timeout').format(timeout=timeout)
        except socket.gaierror as ERR:
            return False, self.error_string('socket_error').format(error=str(ERR))
        except Exception as ERR:
            return False, self.error_string('dns_error').format(error=str(ERR))
        finally:
            sock.close()
                   
    def __parse_mx_response(self,domain:str,response:bytes)->typing.List[typing.Tuple[str,int]]:
        """Parse the MX records response"""
        mx_servers = []
        try:
            answer_count = int.from_bytes(response[6:8], "big")
            _, offset = self.__parse_domain_name(response, 12)  # Pula o cabeçalho e a seção de pergunta
            offset += 4  # tipo e classe (2 bytes cada)
            for _ in range(answer_count):
                if offset >= len(response):
                    self.__debug(self.error_string('malformed_response').format(domain=domain,offset=offset,response=response))
                    break
                name, offset = self.__parse_domain_name(response, offset) # Nome do RR (pode ser ponteiro)
                if offset+10 > len(response):
                    self.__debug(self.error_string('malformed_response_incomplete').format(domain=domain,offset=offset,response=response))
                    break
                rr_type = int.from_bytes(response[offset:offset+2],'big')
                rr_class = int.from_bytes(response[offset+2:offset+4],'big')
                rr_ttl = int.from_bytes(response[offset+4:offset+8],'big')
                rdlength = int.from_bytes(response[offset+8:offset+10],'big')
                offset += 10
                if offset+rdlength > len(response):
                    self.__debug(self.error_string('malformed_response_rdlength').format(domain=domain,offset=offset,rdlength=rdlength,response=response))
                    break
                if rr_type == 15:  # MX
                    if rdlength < 3:
                        self.__debug(self.error_string('mx_record_too_short').format(domain=domain,rdlength=rdlength,response=response))
                        offset += rdlength
                        continue
                    priority = int.from_bytes(response[offset:offset+2],'big')
                    mx_record, _ = self.__parse_domain_name(response, offset+2)
                    mx_record = mx_record.lower().strip()
                    if mx_record == "":
                        self.__debug(self.error_string('mx_found_empty_record').format(priority=priority,domain=domain))
                    elif self.__is_valid_ipaddr(mx_record):
                        self.__debug(self.error_string('mx_found_ip_address').format(ip_address=mx_record,domain=domain))
                    elif mx_record in self.__MX_IGNORE_LIST:
                        self.__debug(self.error_string('mx_found_ignore_list').format(mx_record=mx_record,domain=domain))
                    else:
                        mx_servers.append((mx_record, priority))
                elif rr_type == 5:  # CNAME NO APEX DA ZONA
                    cname, _ = self.__parse_domain_name(response, offset)
                    self.__debug(self.error_string('mx_found_cname').format(cname=cname,domain=domain,response=response))
                else:
                    self.__debug(self.error_string('mx_unsupported_rr_type').format(rr_type=rr_type,domain=domain,response=response))
                offset += rdlength
        except Exception as ERR:
            self.__debug(self.error_string('dns_response_parse_error_mx').format(domain=domain,error=str(ERR),response=response))
        return list(set(mx_servers))
       
    def __resolve_hostname(self,hostname:str,domain:str)->str:
        """Resolve the hostname to an IP address."""
        hostname = hostname.lower().strip()
        query = self.__build_query(hostname, 1)  # Tipo A
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(query, (self.dns_server, 53))    # Verificar se o domínio existe
            response, _ = sock.recvfrom(512)
            flags = struct.unpack(">H", response[2:4])[0]
            rcode = flags & 0x000F
            if rcode != 0:
                return False, self.error_string(rcode).format(domain=hostname)
            answer_count = struct.unpack(">H", response[6:8])[0]
            if answer_count == 0:
                return False, []
            ips_response = self.__parse_hostname_dns_response(hostname,domain,response)
            if len(ips_response) == 0:
                return False, []
            return True, ips_response
        except socket.timeout:
            if self.fallback_dns_server is not None:
                self.__debug(self.error_string('using_fallback_dns_server_hostname').format(dns_server=self.fallback_dns_server,hostname=hostname,domain=domain))
                try:
                    sock.settimeout(self.timeout*2)  # double timeout
                    sock.sendto(query, (self.fallback_dns_server, 53))    # Verificar se o domínio existe
                    response, _ = sock.recvfrom(512)
                    flags = struct.unpack(">H", response[2:4])[0]
                    rcode = flags & 0x000F
                    if rcode != 0:
                        return False, self.error_string(rcode).format(domain=hostname)
                    answer_count = struct.unpack(">H", response[6:8])[0]
                    if answer_count == 0:
                        return False, []
                    ips_response = self.__parse_hostname_dns_response(hostname,domain,response)
                    if len(ips_response) == 0:
                        return False, []
                    return True, ips_response
                except socket.timeout as ERR:
                    return False, self.error_string('timeout').format(timeout=(self.timeout*2)+self.timeout)
                except Exception as ERR:
                    return False, self.error_string('dns_error').format(error=str(ERR))
            else:
                return False, self.error_string('timeout').format(timeout=self.timeout)
        except Exception as ERR:
            return False, self.error_string('dns_error').format(error=str(ERR))
        finally:
            sock.close()
        
    def __parse_hostname_dns_response(self,hostname:str,domain:str,response:bytes)->typing.List[str]:
        """Parse the DNS response and return the IP addresses."""
        try:
            ips = []
            transaction_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", response[:12])
            idx = 12 # skip the header section
            for _ in range(qdcount): #  skip the question section
                while response[idx] != 0:
                    idx += response[idx]+1
                idx += 1  # skip the final byte 0 
                idx += 4  # skip QTYPE (2 bytes) and QCLASS (2 bytes)
            for _ in range(ancount):
                name = struct.unpack(">H", response[idx:idx+2])[0]
                idx += 2
                type_ = struct.unpack(">H", response[idx:idx+2])[0]
                idx += 2
                class_ = struct.unpack(">H", response[idx:idx+2])[0]
                idx += 2
                ttl = struct.unpack(">I", response[idx:idx+4])[0]
                idx += 4
                rdlength = struct.unpack(">H", response[idx:idx+2])[0]
                idx += 2
                rdata = response[idx:idx+rdlength]
                idx += rdlength
                if type_ == 1 and class_ == 1:  # Type A and Class IN
                    ip_address = socket.inet_ntoa(rdata)
                    ips.append(ip_address)
            return ips
        except Exception as ERR:    
            self.__debug(self.error_string('dns_response_parse_error_hostname').format(hostname=hostname,domain=domain,error=str(ERR),response=response))
            return []

