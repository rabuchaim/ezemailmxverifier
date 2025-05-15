#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time, concurrent.futures
from ezemailmxverifier import EzEmailMXVerifier,safe_timeout_decorator

class myNewEzEmailMXVerifier(EzEmailMXVerifier):
    def __apply_safe_timeout_decorator(self):
        self.__verify_mx_records = safe_timeout_decorator(10)(self.__verify_mx_records)
        self.__verify_soa_domain = safe_timeout_decorator(10)(self.__verify_soa_domain)
    
def thread_emailverifier_verify_email(email:str,counter:int):
    start_time = time.monotonic()
    result,error_message,mx_records = emailverifier_object.verify_email(email)
    return (email,result,error_message,mx_records,counter,"[%.9f]"%(time.monotonic()-start_time))

def thread_emailverifier_verify_domain(domain:str,counter:int):
    start_time = time.monotonic()
    result,error_message,soa_records = emailverifier_object.verify_domain(domain)
    return (domain,result,error_message,soa_records,counter,"[%.9f]"%(time.monotonic()-start_time))

if __name__ == "__main__":
    emailverifier_object = EzEmailMXVerifier(
    # emailverifier_object = myNewEzEmailMXVerifier(
                                        dns_server='8.8.8.8',
                                        fallback_dns_server='1.1.1.1',
                                        return_boolean=False,
                                        timeout=1,
                                        timeout_max_retries=2,
                                        safe_timeout_enabled=False,
                                        debug=True,
                                        use_mx_cache=True,
                                        use_resolver_cache=True,
                                        use_soa_domain_cache=True,
                                        # debug_flag_file_watchdog_interval=5,
                                        verify_tld=True,
                                        tld_datfile_auto_update_days=3,
    )                                         
    
    emailverifier_object.error_string.update_error_strings({"valid_domain": "UHUL!!! IS A VALID DOMAIN!!!"})
    emailverifier_object.error_string.update_error_strings({"valid_email_mx_ok": "IT's A NICE AND VALID EMAIL ADDRESS!!!"})

    # emailverifier_object.tld.fetch()
    with open("db_test.txt", "r") as f:
        counter = 0
    # with open("db_test_long_timeout.txt", "r") as f:
        for line in f:
            if line.startswith('#') or line.strip() == '':
                continue
            start_time = time.monotonic()
            counter += 1
            email = line.lower().strip()
            result,error_message,mx_records = emailverifier_object.verify_email(email)
            print(f"{counter}. {email.ljust(40)} - {'[%.9f]'%(time.monotonic()-start_time)} - {result,error_message,mx_records}", flush=True)
    
    quit()
    
    # using threads
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        with open("db_test.txt", "r") as f:
        # with open("db_test_long_timeout.txt", "r") as f:
            counter = 0
            futures = []
            for line in f:
                if line.startswith('#') or line.strip() == '':
                    continue
                counter += 1
                email = line.lower().strip()
                futures.append(executor.submit(thread_emailverifier_verify_email,email,counter))
                
                # try:
                #     local_part,domain = email.split("@")
                #     futures.append(executor.submit(thread_emailverifier_verify_domain,domain,counter))
                # except:
                #     continue
                
                # if counter >= 1000:
                #     break
                
        for future in futures:
            result = future.result()
            email,result,error_message,mx_records,counter,elapsed_time = result
            print(f"{counter}. {email.ljust(40)} - {elapsed_time} - {result,error_message}", flush=True)
            # print(f"{counter}. {email.ljust(40)} - {elapsed_time} - {result,error_message,mx_records}", flush=True)

            # domain,result,error_message,soa_records,counter,elapsed_time = result
            # print(f"{counter}. {domain.ljust(40)} - {elapsed_time} - {result,error_message}", flush=True)
