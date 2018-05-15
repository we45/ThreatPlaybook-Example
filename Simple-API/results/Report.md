# Customer API
## Threat Model for: Customer API
### Process Flow Diagram
![Flow Diagram](/Users/abhaybhargav/Documents/Code/Python/TPExample/Simple-API/results/diagram.svg)
## Threat Models
### Functionality: create_customer_profile
As an end-user, I would like to create customer profile and upload information to the customer profile. This will have the customer's PII
#### Abuse Cases

##### As a malicious user, I would render the upload and API system unavailable to the organization
**Upload file with malware that brings down the system or subjects it to ransomware, DREAD: 8**
##### Test Cases
| Description | type | tags |
|----------|:----------:|:--------:|
| Check for Template Injection with Burp | Automated Test | burp,tplmap |
| run nmap with nse and vuln_discovery | Automated Test | nmap |
| check for XXE in file upload with ZAP | Automated Test | zap,burp,arachni |
| check manually for upload of files of all types and sizes | Manual Test | manual |


##### As a malicious user, I would like to steal customer PII from the uploaded files for me to be able to monetize this information
**Upload file with malware that brings down the system or subjects it to ransomware, DREAD: 8**
##### Test Cases
| Description | type | tags |
|----------|:----------:|:--------:|
| Check for Template Injection with Burp | Automated Test | burp,tplmap |
| run nmap with nse and vuln_discovery | Automated Test | nmap |
| check for XXE in file upload with ZAP | Automated Test | zap,burp,arachni |
| check manually for upload of files of all types and sizes | Manual Test | manual |
**Attacker would enumerate for Public Bucket Access of Uploaded files and Generic Authenticated Access to AWS, DREAD: 8**
##### Test Cases
| Description | type | tags |
|----------|:----------:|:--------:|
| check if AWS s3 bucket is publicly accessible | Automated Test | burp,s3-inspector |
| check manually for upload of files of all types and sizes | Manual Test | manual |
**Upload file with malware that gives you backend access to the Uploaded files, based on malicious file execution, DREAD: 8**
##### Test Cases
| Description | type | tags |
|----------|:----------:|:--------:|
| run nmap with nse and vuln_discovery | Automated Test | nmap |
| check for XXE in file upload with ZAP | Automated Test | zap,burp,arachni |
| check manually for upload of files of all types and sizes | Manual Test | manual |
**User/Attacker would attempt to perform SQL Injection, Command Injection, Template Injection Attacks to compromise the service and gain access to sensitive datasets, DREAD: 10**
##### Test Cases
| Description | type | tags |
|----------|:----------:|:--------:|
| Use Automated Vulnerability Scanners to test for SQL Injection | Automated Test | zap,burp,arachni |
| Check for Template Injection with Burp | Automated Test | burp,tplmap |
| check for XXE in file upload with ZAP | Automated Test | zap,burp,arachni |



### Functionality: login_user
As an employee of the organization,
I would like to login to the Customer API and manage Customer Information

#### Abuse Cases

##### As an external attacker, I would compromise a single/multiple user accounts to gain access to sensitive customer information
**Attacker attempts to steal Auth Token from user with malicious client-side script. Target is any front-end using the API, DREAD: 8**
##### Test Cases
| Description | type | tags |
|----------|:----------:|:--------:|
| check for manual XSS persistent | Manual Test | zap,burp,arachni |
| check for persistent XSS with ZAP | Automated Test | zap,burp,arachni |
| check for reflected XSS ZAP | Automated Test | zap,burp,arachni |
| check for manual XSS reflected | Manual Test | manual |
**External attacker may be able to bypass user authentication by compromising weak passwords of users, DREAD: 7**
##### Test Cases
| Description | type | tags |
|----------|:----------:|:--------:|
| Check for Default passwords for ZAP Fuzzer | Automated Test | nmap,zap,burp,arachni |
| Check for weak passwords for ZAP Fuzzer | Automated Test | zap,burp,arachni |
**External attacker may be able to bypass user authentication by compromising default passwords of users, DREAD: 9**
##### Test Cases
| Description | type | tags |
|----------|:----------:|:--------:|
| Check for Default passwords for ZAP Fuzzer | Automated Test | nmap,zap,burp,arachni |
**External Attacker may be able to gain access to user accounts by successfully performing SQL Injection Attacks against some of the unauthenticated API Endpoints in the application, DREAD: 8**
##### Test Cases
| Description | type | tags |
|----------|:----------:|:--------:|
| Use Automated Vulnerability Scanners to test for SQL Injection | Automated Test | zap,burp,arachni |
| Attempt to force generic Error Messages, especially 500 Errors | Automated Test | zap,burp,arachni |
| check database for low-priv users, authorization and hardening | Automated Test | nessus,nmap |
**Attacker attempts to compromise auth token by gaining access to the end user's auth token by performing Man in the Middle Attacks, DREAD: 8**
##### Test Cases
| Description | type | tags |
|----------|:----------:|:--------:|
| tests against SSL with SSLLabs.com, Burp and Zap | Automated Test | burp,zap,ssllab |



## Vulnerabilities

### Advanced SQL Injection - AND boolean-based blind - WHERE or HAVING clause
CWE: 89, Severity: High

### Linked Threat Models
* injection attacks
* sql injection user account access

#### Description
A SQL injection may be possible using the attached payload
#### Remediation
Do not trust client side input, even if there is client side validation in place.
In general, type check all data on the server side.
If the application uses JDBC, use PreparedStatement or CallableStatement, with parameters passed by '?'
If the application uses ASP, use ADO Command Objects with strong type checking and parameterized queries.
If database Stored Procedures can be used, use them.
Do *not* concatenate strings into queries in the stored procedure, or use 'exec', 'exec immediate', or equivalent functionality!
Do not create dynamic SQL queries using simple string concatenation.
Escape all data received from the client.
Apply a 'whitelist' of allowed characters, or a 'blacklist' of disallowed characters in user input.
Apply the privilege of least privilege by using the least privileged database user possible.
In particular, avoid using the 'sa' or 'db-owner' database users. This does not eliminate SQL injection, but minimizes its impact.
Grant the minimum database access that is necessary for the application.
### Evidences
| URL | Parameter | other info & attack |
|----------|:----------:|:--------:|
| POST : http://localhost:5050/search | search | The page results were successfully manipulated using the boolean conditions [dleon' AND 1361=1361 AND 'vtfQ'='vtfQ] and [dleon' AND 5960=1618 AND 'Dtpn'='Dtpn]
The parameter value being modified was stripped from the HTML output for the purposes of the comparison.
Data was returned for the original parameter.
The vulnerability was detected by successfully restricting the data originally returned, by manipulating the parameter., dleon' AND 1361=1361 AND 'vtfQ'='vtfQ |
### Cross Site Scripting (Reflected)
CWE: 79, Severity: High

### Linked Threat Models
* auth token hijack xss

#### Description
Cross-site Scripting (XSS) is an attack technique that involves echoing attacker-supplied code into a user's browser instance. A browser instance can be a standard web browser client, or a browser object embedded in a software product such as the browser within WinAmp, an RSS reader, or an email client. The code itself is usually written in HTML/JavaScript, but may also extend to VBScript, ActiveX, Java, Flash, or any other browser-supported technology.
When an attacker gets a user's browser to execute his/her code, the code will run within the security context (or zone) of the hosting web site. With this level of privilege, the code has the ability to read, modify and transmit any sensitive data accessible by the browser. A Cross-site Scripted user could have his/her account hijacked (cookie theft), their browser redirected to another location, or possibly shown fraudulent content delivered by the web site they are visiting. Cross-site Scripting attacks essentially compromise the trust relationship between a user and the web site. Applications utilizing browser object instances which load content from the file system may execute code under the local machine zone allowing for system compromise.

There are three types of Cross-site Scripting attacks: non-persistent, persistent and DOM-based.
Non-persistent attacks and DOM-based attacks require a user to either visit a specially crafted link laced with malicious code, or visit a malicious web page containing a web form, which when posted to the vulnerable site, will mount the attack. Using a malicious form will oftentimes take place when the vulnerable resource only accepts HTTP POST requests. In such a case, the form can be submitted automatically, without the victim's knowledge (e.g. by using JavaScript). Upon clicking on the malicious link or submitting the malicious form, the XSS payload will get echoed back and will get interpreted by the user's browser and execute. Another technique to send almost arbitrary requests (GET and POST) is by using an embedded client, such as Adobe Flash.
Persistent attacks occur when the malicious code is submitted to a web site where it's stored for a period of time. Examples of an attacker's favorite targets often include message board posts, web mail messages, and web chat software. The unsuspecting user is not required to interact with any additional site/link (e.g. an attacker site or a malicious link sent via email), just simply view the web page containing the code.
#### Remediation
Phase: Architecture and Design
Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.
Examples of libraries and frameworks that make it easier to generate properly encoded output include Microsoft's Anti-XSS library, the OWASP ESAPI Encoding module, and Apache Wicket.

Phases: Implementation; Architecture and Design
Understand the context in which your data will be used and the encoding that will be expected. This is especially important when transmitting data between different components, or when generating outputs that can contain multiple encodings at the same time, such as web pages or multi-part mail messages. Study all expected communication protocols and data representations to determine the required encoding strategies.
For any data that will be output to another web page, especially any data that was received from external inputs, use the appropriate encoding on all non-alphanumeric characters.
Consult the XSS Prevention Cheat Sheet for more details on the types of encoding and escaping that are needed.

Phase: Architecture and Design
For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side, in order to avoid CWE-602. Attackers can bypass the client-side checks by modifying values after the checks have been performed, or by changing the client to remove the client-side checks entirely. Then, these modified values would be submitted to the server.

If available, use structured mechanisms that automatically enforce the separation between data and code. These mechanisms may be able to provide the relevant quoting, encoding, and validation automatically, instead of relying on the developer to provide this capability at every point where output is generated.

Phase: Implementation
For every web page that is generated, use and specify a character encoding such as ISO-8859-1 or UTF-8. When an encoding is not specified, the web browser may choose a different encoding by guessing which encoding is actually being used by the web page. This can cause the web browser to treat certain sequences as special, opening up the client to subtle XSS attacks. See CWE-116 for more mitigations related to encoding/escaping.

To help mitigate XSS attacks against the user's session cookie, set the session cookie to be HttpOnly. In browsers that support the HttpOnly feature (such as more recent versions of Internet Explorer and Firefox), this attribute can prevent the user's session cookie from being accessible to malicious client-side scripts that use document.cookie. This is not a complete solution, since HttpOnly is not supported by all browsers. More importantly, XMLHTTPRequest and other powerful browser technologies provide read access to HTTP headers, including the Set-Cookie header in which the HttpOnly flag is set.

Assume all input is malicious. Use an "accept known good" input validation strategy, i.e., use a whitelist of acceptable inputs that strictly conform to specifications. Reject any input that does not strictly conform to specifications, or transform it into something that does. Do not rely exclusively on looking for malicious or malformed inputs (i.e., do not rely on a blacklist). However, blacklists can be useful for detecting potential attacks or determining which inputs are so malformed that they should be rejected outright.

When performing input validation, consider all potentially relevant properties, including length, type of input, the full range of acceptable values, missing or extra inputs, syntax, consistency across related fields, and conformance to business rules. As an example of business rule logic, "boat" may be syntactically valid because it only contains alphanumeric characters, but it is not valid if you are expecting colors such as "red" or "blue."

Ensure that you perform input validation at well-defined interfaces within the application. This will help protect the application even if a component is reused or moved elsewhere.
### Evidences
| URL | Parameter | other info & attack |
|----------|:----------:|:--------:|
| POST : http://localhost:5050/search | search | , '"<script>alert(1);</script> |
### HTTP Only Site
CWE: 311, Severity: Medium

### Linked Threat Models
* auth token hijacking mitm

#### Description
The site is only served under HTTP and not HTTPS.
#### Remediation
Configure your web or application server to use SSL (https).
### Evidences
| URL | Parameter | other info & attack |
|----------|:----------:|:--------:|
| GET : http://localhost:5050/ |  | Failed to connect.
ZAP attempted to connect via: https://localhost:443/,  |
### Integer Overflow Error
CWE: 190, Severity: Medium

#### Description
An integer overflow condition exists when an integer, which has not been properly checked from the input stream is used within a compiled program.
#### Remediation
Rewrite the background program using proper checking of the size of integer being input to prevent overflows and divide by 0 errors.  This will require a recompile of the background executable.
### Evidences
| URL | Parameter | other info & attack |
|----------|:----------:|:--------:|
| POST : http://localhost:5050/fetch/customer | id | Potential Integer Overflow.  Status code changed on the input of a long string of random integers., 99945105638671108106901850563893412340933543 |
### X-Frame-Options Header Not Set
CWE: 16, Severity: Medium

#### Description
X-Frame-Options header is not included in the HTTP response to protect against 'ClickJacking' attacks.
#### Remediation
Most modern Web browsers support the X-Frame-Options HTTP header. Ensure it's set on all web pages returned by your site (if you expect the page to be framed only by pages on your server (e.g. it's part of a FRAMESET) then you'll want to use SAMEORIGIN, otherwise if you never expect the page to be framed, you should use DENY. ALLOW-FROM allows specific websites to frame the web page in supported web browsers).
### Evidences
| URL | Parameter | other info & attack |
|----------|:----------:|:--------:|
| GET : http://localhost:5050/ | X-Frame-Options | ,  |
### Web Browser XSS Protection Not Enabled
CWE: 933, Severity: Low

#### Description
Web Browser XSS Protection is not enabled, or is disabled by the configuration of the 'X-XSS-Protection' HTTP response header on the web server
#### Remediation
Ensure that the web browser's XSS filter is enabled, by setting the X-XSS-Protection HTTP response header to '1'.
### Evidences
| URL | Parameter | other info & attack |
|----------|:----------:|:--------:|
| GET : http://localhost:5050/ | X-XSS-Protection | The X-XSS-Protection HTTP response header allows the web server to enable or disable the web browser's XSS protection mechanism. The following values would attempt to enable it: 
X-XSS-Protection: 1; mode=block
X-XSS-Protection: 1; report=http://www.example.com/xss
The following values would disable it:
X-XSS-Protection: 0
The X-XSS-Protection HTTP response header is currently supported on Internet Explorer, Chrome and Safari (WebKit).
Note that this alert is only raised if the response body could potentially contain an XSS payload (with a text-based content type, with a non-zero length).,  |
### X-Content-Type-Options Header Missing
CWE: 16, Severity: Low

#### Description
The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.
#### Remediation
Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.
If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.
### Evidences
| URL | Parameter | other info & attack |
|----------|:----------:|:--------:|
| POST : http://localhost:5050/search | X-Content-Type-Options | This issue still applies to error type pages (401, 403, 500, etc) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scanner will not alert on client or server error responses.,  |
| POST : http://localhost:5050/search | X-Content-Type-Options | This issue still applies to error type pages (401, 403, 500, etc) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scanner will not alert on client or server error responses.,  |
| POST : http://localhost:5050/search | X-Content-Type-Options | This issue still applies to error type pages (401, 403, 500, etc) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scanner will not alert on client or server error responses.,  |
| POST : http://localhost:5050/search | X-Content-Type-Options | This issue still applies to error type pages (401, 403, 500, etc) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scanner will not alert on client or server error responses.,  |
| POST : http://localhost:5050/search | X-Content-Type-Options | This issue still applies to error type pages (401, 403, 500, etc) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scanner will not alert on client or server error responses.,  |
## Reconnaissance

### Reconnaissance Tool: nmap
#### Linked Test Cases
* nmap_vulnerability_scan - run nmap with nse and vuln_discovery
* system_hardening_checks - run system hardening check tools to identify vulnerabilities
* database_hardening_check - check database for low-priv users, authorization and hardening
* default_passwords - Check for Default passwords for ZAP Fuzzer
* nmap_all_tcp_ports - run nmap against all tcp ports
* network_segmentation_checks - check for network segmentation

#### Target: CRM_Application

```

# Nmap 7.60 scan initiated Sun May 13 18:04:15 2018 as: /usr/local/bin/nmap -oX - -vvv --stats-every 1s -oN /Users/abhaybhargav/Documents/Code/Python/TPExample/Simple-API/results/flask.txt localhost
Warning: Hostname localhost resolves to 2 IPs. Using 127.0.0.1.
Nmap scan report for localhost (127.0.0.1)
Host is up, received conn-refused (0.00084s latency).
Other addresses for localhost (not scanned): ::1
Scanned at 2018-05-13 18:04:15 PDT for 3s
Not shown: 498 closed ports, 496 filtered ports
Reason: 498 conn-refused and 496 no-responses
PORT      STATE SERVICE      REASON
22/tcp    open  ssh          syn-ack
631/tcp   open  ipp          syn-ack
5050/tcp  open  mmcc         syn-ack
8090/tcp  open  opsmessaging syn-ack
9000/tcp  open  cslistener   syn-ack
49155/tcp open  unknown      syn-ack

Read data files from: /usr/local/bin/../share/nmap
# Nmap done at Sun May 13 18:04:18 2018 -- 1 IP address (1 host up) scanned in 2.63 seconds

```
### Reconnaissance Tool: wfuzz
#### Linked Test Cases
* brute_directories - bruteforce directories with tools

#### Target: CRM_Application

