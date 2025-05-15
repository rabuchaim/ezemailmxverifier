# EzEmailMXVerifier v1.0.0

`ezemailmxverifier` is a fast, complete and pure Python library to validate email addresses. 

It can check only the syntax of the email address, or only the syntax of the domain including the Top Level Domain (always updated). It can also check only if a domain has been registered or not and it can also check if an email address has a registered and valid domain and if there are MX servers assigned to that domain and if at least 1 configured MX server is valid. 

With this class, you will never receive an Exception. Every error is pre-handled and you will receive details about any email or domain validation failure.

All this without needing any other auxiliary library, it has its own DNS client with a fallback server in case of timeout on the main server and configuration of retries in case of timeout. DNS resolutions also have a SmartCache if the class is being used to validate thousands of email addresses, which makes it very fast and an email address of a domain already verified can be validated in less than 0.00005 seconds.

It also has its own class to check if the Top Level Domain is valid and with auto-update in milliseconds (Our modified code from publicsuffix2 package).

You can also easily translate class messages into your language :) 

<!-- ```
What's new in v1.0.1 - xx/xxx/2025
- xxxxxxx
``` -->

---

## 🚀 Installation

```bash
pip install ezemailmxverifier
```

---

## 🔧 Requirements

- Python 3.10+ and nothing more!

---

## 🖉 `EzEmailMXVerifier` Class Parameters

For most uses, you do not need to change any class parameters.

| Parameter                             | Type          | Default Value               | Description                              |
| ------------------------------------- | ------------- | --------------------------- | ---------------------------------------- |
| `dns_server`                          | `str`         | `'8.8.8.8'`                 | A default DNS Server to lookup  |
| `fallback_dns_server`                 | `str`         | `'1.1.1.1'`                 | The fallback DNS server in case of timeout in Default DNS Server|
| `timeout`                             | `float`       | `1.0`                       | Timeout (in seconds) |
| `timeout_max_retries`                 | `int`         | `2`                         | Max retries if the first try receives a timeout |
| `safe_timeout_enabled`                | `bool`        | `False`                     | A timeout mecanism based on multiprocessing |
| `mx_ignore_list`                      | `list`        | `None`                      | A list with MX servers hostnames to be ignored |
| `return_boolean`                      | `bool`        | `False`                     | If enabled, return only True or False |
| `use_mx_cache`                        | `bool`        | `True`                      | A smart cache for resolved MX records |
| `use_resolver_cache`                  | `bool`        | `True`                      | A smart cache for resolved hostnames |
| `use_soa_domain_cache`                | `bool`        | `True`                      | A smart cache for resolved domains |
| `verify_tld`                          | `bool`        | `True`                      | Verify the top level domain (.com, .com.br, .co.uk, etc) |
| `tld_datfile_dest_dir`                | `str`         | `os.path.dirname(__file__)` | The directory of public_suffix_list.dat.gz |
| `tld_datfile_auto_update_days`        | `int`         | `3`                         | Auto update for file public_suffix_list.dat.gz |
| `debug`                               | `bool`        | `False`                     | Enable debug messages |
| `debug_flag_file_watchdog_interval`   | `int`         | `5`                         | Interval to check the existence of file ezemailmxverifier_debug |
| `debug_flag_file_dir`                 | `str`         | `os.path.dirname(__file__)` | The directory to watch for debug flag file  |
| `debug_flag_file_name`                | `str`         | `ezemailmxverifier_debug`   | The filename to enable the debug on the fly |
| `debug_save_dir`                      | `str`         | `tempfile.gettempdir()`     | A directory to save the cache information in debug mode |

### Class Parameters Instructions

- `dns_server` and `fallback_dns_server`: Avoid using servers from the same provider. Always use one from Google and another from CloudFlare, for example. Below are some recommended public DNS servers:

    | Provider  | IPs                           | Fast   | Privacy?          |
    | --------- | ----------------------------- | ----- | ----------------- |
    | Google    | `8.8.8.8` and `8.8.4.4`           | ✅    | ❌(partial logs) |
    | CloudFlare    | `1.1.1.1` and `1.0.0.1`           | ✅✅    | ✅✅ |
    | Quad9    | `9.9.9.9` and `149.112.112.112`           | ✅    | ✅ |
    | OpenDNS    | `208.67.222.222` and `208.67.220.220`           | ✅    | ❌(logs Cisco) |

- `timeout_max_retries`: This is the number of retries in addition to the main attempt. It only occurs in case of timeout of the previous attempts. If you only want a single attempt, set this value to zero.

- `safe_timeout_enabled`: Use this function ONLY if you are experiencing long socket hangings, such as the function taking much longer than the time set in the timeout to present the timeout (considering the configured retries). Using this function can increase the elapsed time. The timeout of this function is calculated by (timeout*4) per retry. This allows this function to work with threads (the safe_timeout made with signals only works on the main thread). 

- `mx_ignore_list`: Enter here any MX server that you want to ignore. By default, it is already configured to ignore the servers `'localhost'`, `'0.0.0.0'`, `'~'` which are hostnames normally entered to indicate that email sending is disabled. After creating the object, you can add or modify this list with the methods `get_mx_ignore_list()->list` and `set_mx_ignore_list(a_list)->bool`.

```python
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
```

- `return_boolean`: If enabled, the email and domain verification functions will only return `True` or `False`. If disabled, the functions will always return a tuple with the `Result (True or False)`, `Error Message (string)`, `Data (mx records list[dict] or soa record {dict})`

- `use_mx_cache`: A SmartCache to store MX queries of already verified domains. If debug mode is enabled, the cache will be saved every 10 seconds in the directory specified in the `debug_save_dir` parameter so you can monitor it. You can access this cache using the methods `self._mx_cache.get_cache()->dict`, `self._mx_cache.cache_info()->CacheInfo["hits","misses","items","size_in_kb"]` and `self._mx_cache.cache_clear()->None`.

- `use_resolver_cache`: A SmartCache to store hostname queries from the servers specified in the domains' MX records. If debug mode is enabled, the cache will be saved every 10 seconds in the directory specified in the `debug_save_dir` parameter so you can monitor it. You can access this cache using the methods `self._resolver_cache.get_cache()->dict`, `self._resolver_cache.cache_info()->CacheInfo["hits","misses","items","size_in_kb"]` and `self._resolver_cache.cache_clear()->None`.

- `use_soa_domain_cache`: A SmartCache to store domain existence queries. We use the SOA record existence check instead of a whois query and this works for subdomains as well (e.g. marketing@mktg.mydomain.com). If debug mode is enabled, the cache will be saved every 10 seconds to the directory specified in the `debug_save_dir` parameter so you can monitor it. You can access this cache using the methods `self._soa_domain_cache.get_cache()->dict`, `self._soa_domain_cache.cache_info()->CacheInfo["hits","misses","items","size_in_kb"]` and `self._soa_domain_cache.cache_clear()->None`.

    > The `cache_info()` method returns a NamedTuple, that is, you access the properties by calling them directly, for example: `print(self._resolver_cache.cache_info().hits)`, `print(self._resolver_cache.cache_info().misses)`, `print(self._resolver_cache.cache_info().items)` or `print(self._resolver_cache.cache_info().size_in_kb)`
    ```python 
    def cache_info(self):
        CacheInfo = collections.namedtuple("CacheInfo",["hits","misses","items","size_in_kb"])
        return CacheInfo(self.__stats['hits'],self.__stats['misses'],self.__stats['items'],self.__total_size(self.__cache))
    ```

- `verify_tld`: Checks the Top Level Domain (.com, .com.br, etc) of the queried domains. We use a reduced and modified code from the `publicsuffix2` library. This data is updated frequently by the Mozilla Foundation, so there is a method to force the update called `self.tld.fetch()` that takes milliseconds. The code downloads the new TLD information, compiles it, and writes it to the `public_suffix_list.dat.gz` file (~40kb).

    - `tld_datfile_dest_dir`: Here you enter the directory where the `public_suffix_list.dat.gz` file will be saved. By default, it is the same directory as the library `os.path.dirname(__file__)`, so make sure the application has permission to write to this directory, otherwise you can enter the `/tmp` directory for example.

    - `tld_datfile_auto_update_days`: If the class finds that the `public_suffix_list.dat.gz` file is out of date, it will automatically update it. We have noticed that this file changes every 3 days, about 2 times per week.

- `debug`: Activates debug mode, and when this happens many messages in yellow will be displayed in the console detailing each step of what the class is doing to check your email, domain or MX, including messages whether cache was used or not. You can also change the debug mode with the environment variable `ezemailmxverifier_debug` to `true` if you are using this class in AWS Lambda functions (all lowercase, including the environment variable name). **The environment variable, when existing, overrides the `debug=False` value informed when creating the object.**

    - `debug_flag_file_watchdog_interval`: This function only works if you created the object with the `debug=False` option. It allows you to enable or disable debug mode on-the-fly while your application is running. To enable debugging, simply create a file `ezemailmxverifier_debug` in the directory specified in the `debug_flag_file_dir` parameter. To disable debugging, simply remove the file `ezemailmxverifier_debug`. **Be careful not to remove the application's .py file (I did it)!!!** To disable this function, enter the value zero. **If you create the EzEmailMXVerifier object with the `debug=True` function, this function of changing the debug mode on-the-fly is disabled.**

    - `debug_flag_file_dir`: Enter the directory where the debug flag file will be monitored. Default is `os.path.dirname(__file__)`

    - `debug_flag_file_name`: To avoid accidents, you can change the name of the debug flag file to be monitored. Default is `ezemailmxverifier_debug`.

- `debug_save_dir`: Enter the directory where the cache and statistics information will be saved if the debug mode is enabled. Default is `/tmp/`

---

## 📑 Usage Example

---

## 📑 Translating all messages

After creating the `EzEmailMXVerifier` object, you can change the content of any error message using the `error_strings` property. Keep the same values ​​between curly braces as they will be formatted when displayed.
> **PLEASE do not translate any word "timeout" as it is used to indicate that there was a timeout and the fallback server should be triggered or a retry should be performed.**

```python
>>> email_verifier = EzEmailMXVerifier()
# returns a dict with all error code and error messages
>>> print(email_verifier.error_strings) 
# It is also a __call__() method of the class
>>> print(email_verifier.error_strings('valid_email_mx_ok'))
"Valid Email sintax with valid MX records for domain {domain}"
>>> print(email_verifier.error_strings('valid_email_no_mx'))
"Valid Email sintax but no MX records found for domain {domain}",
# to update a specific error message
>>> email_verifier.error_strings.update_error_string('valid_email_mx_ok','Sintaxe de e-mail válida com registros MX válidos para domínio {domain}') 
>>> email_verifier.error_strings.update_error_string('valid_email_no_mx','Sintaxe de e-mail válida, mas nenhum registro MX encontrado para o domínio {domain}') 
```
Other functions of the EzEmailMXVerifierErrorStrings subclass:
```python
self.error_strings # a dict property for the error messages
self.dns_rcodes    # a dict property for the DNS query return error messages
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
```
---

## 🌐 Links

- **GitHub**: [github.com/rabuchaim/ezemailmxverifier](https://github.com/rabuchaim/ezemailmxverifier)
- **PyPI**: [pypi.org/project/ezemailmxverifier](https://pypi.org/project/ezemailmxverifier)
- **Bugs / Issues**: [issues page](https://github.com/rabuchaim/ezemailmxverifier/issues)

---

## ⚖️ License

MIT License

---

## 🙌 Author

Ricardo Abuchaim ([ricardoabuchaim@gmail.com](mailto\:ricardoabuchaim@gmail.com)) - [github.com/rabuchaim](https://github.com/rabuchaim)

---

Contributions, testing, ideas, or feedback are very welcome! 🌟
