/**
 * OWASP Top 10 2021 CWE mappings
 */
export const OWASP_TOP_10_MAPPINGS = {
  'A01:2021': {
    name: 'Broken Access Control',
    cwes: [
      { cwe: 'CWE-22', name: 'Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)' },
      { cwe: 'CWE-23', name: 'Relative Path Traversal' },
      { cwe: 'CWE-35', name: 'Path Traversal: \'.../.../\'/\'' },
      { cwe: 'CWE-59', name: 'Improper Link Resolution Before File Access (Link Following)' },
      { cwe: 'CWE-200', name: 'Exposure of Sensitive Information to an Unauthorized Actor' },
      { cwe: 'CWE-201', name: 'Exposure of Sensitive Information Through Sent Data' },
      { cwe: 'CWE-219', name: 'Storage of File with Sensitive Data Under Web Root' },
      { cwe: 'CWE-264', name: 'Permissions, Privileges, and Access Controls (deprecated)' },
      { cwe: 'CWE-275', name: 'Permission Issues' },
      { cwe: 'CWE-276', name: 'Incorrect Default Permissions' },
      { cwe: 'CWE-284', name: 'Improper Access Control' },
      { cwe: 'CWE-285', name: 'Improper Authorization' },
      { cwe: 'CWE-352', name: 'Cross-Site Request Forgery (CSRF)' },
      { cwe: 'CWE-359', name: 'Exposure of Private Personal Information to an Unauthorized Actor' },
      { cwe: 'CWE-377', name: 'Insecure Temporary File' },
      { cwe: 'CWE-402', name: 'Transmission of Private Resources into a New Sphere (Resource Leak)' },
      { cwe: 'CWE-425', name: 'Direct Request (Forced Browsing)' },
      { cwe: 'CWE-441', name: 'Unintended Proxy or Intermediary (Confused Deputy)' },
      { cwe: 'CWE-497', name: 'Exposure of Sensitive System Information to an Unauthorized Control Sphere' },
      { cwe: 'CWE-538', name: 'Insertion of Sensitive Information into Externally-Accessible File or Directory' },
      { cwe: 'CWE-540', name: 'Inclusion of Sensitive Information in Source Code' },
      { cwe: 'CWE-548', name: 'Exposure of Information Through Directory Listing' },
      { cwe: 'CWE-552', name: 'Files or Directories Accessible to External Parties' },
      { cwe: 'CWE-566', name: 'Authorization Bypass Through User-Controlled SQL Primary Key' },
      { cwe: 'CWE-601', name: 'URL Redirection to Untrusted Site (Open Redirect)' },
      { cwe: 'CWE-639', name: 'Authorization Bypass Through User-Controlled Key' },
      { cwe: 'CWE-651', name: 'Exposure of WSDL File Containing Sensitive Information' },
      { cwe: 'CWE-668', name: 'Exposure of Resource to Wrong Sphere' },
      { cwe: 'CWE-706', name: 'Use of Incorrectly-Resolved Name or Reference' },
      { cwe: 'CWE-862', name: 'Missing Authorization' },
      { cwe: 'CWE-863', name: 'Incorrect Authorization' },
      { cwe: 'CWE-913', name: 'Improper Control of Dynamically-Managed Code Resources' },
      { cwe: 'CWE-922', name: 'Insecure Storage of Sensitive Information' },
      { cwe: 'CWE-1275', name: 'Sensitive Cookie with Improper SameSite Attribute' }
    ]
  },
  'A02:2021': {
    name: 'Cryptographic Failures',
    cwes: [
      { cwe: 'CWE-259', name: 'Use of Hard-coded Password' },
      { cwe: 'CWE-261', name: 'Weak Encoding for Password' },
      { cwe: 'CWE-296', name: 'Improper Following of a Certificate\'s Chain of Trust' },
      { cwe: 'CWE-310', name: 'Cryptographic Issues' },
      { cwe: 'CWE-319', name: 'Cleartext Transmission of Sensitive Information' },
      { cwe: 'CWE-321', name: 'Use of Hard-coded Cryptographic Key' },
      { cwe: 'CWE-322', name: 'Key Exchange without Entity Authentication' },
      { cwe: 'CWE-323', name: 'Reusing a Nonce, Key Pair in Encryption' },
      { cwe: 'CWE-324', name: 'Use of a Key Past its Expiration Date' },
      { cwe: 'CWE-325', name: 'Missing Required Cryptographic Step' },
      { cwe: 'CWE-326', name: 'Inadequate Encryption Strength' },
      { cwe: 'CWE-327', name: 'Use of a Broken or Risky Cryptographic Algorithm' },
      { cwe: 'CWE-328', name: 'Reversible One-Way Hash' },
      { cwe: 'CWE-329', name: 'Not Using a Random IV with CBC Mode' },
      { cwe: 'CWE-330', name: 'Use of Insufficiently Random Values' },
      { cwe: 'CWE-331', name: 'Insufficient Entropy' },
      { cwe: 'CWE-335', name: 'Incorrect Usage of Seeds in Pseudo-Random Number Generator (PRNG)' },
      { cwe: 'CWE-336', name: 'Same Seed in Pseudo-Random Number Generator (PRNG)' },
      { cwe: 'CWE-337', name: 'Predictable Seed in Pseudo-Random Number Generator (PRNG)' },
      { cwe: 'CWE-338', name: 'Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)' },
      { cwe: 'CWE-340', name: 'Generation of Predictable Numbers or Identifiers' },
      { cwe: 'CWE-347', name: 'Improper Verification of Cryptographic Signature' },
      { cwe: 'CWE-523', name: 'Unprotected Transport of Credentials' },
      { cwe: 'CWE-720', name: 'OWASP Top Ten 2007 Category A9 - Insecure Communications' },
      { cwe: 'CWE-757', name: 'Selection of Less-Secure Algorithm During Negotiation (Algorithm Downgrade)' },
      { cwe: 'CWE-759', name: 'Use of a One-Way Hash without a Salt' },
      { cwe: 'CWE-760', name: 'Use of a One-Way Hash with a Predictable Salt' },
      { cwe: 'CWE-780', name: 'Use of RSA Algorithm without OAEP' },
      { cwe: 'CWE-818', name: 'Insufficient Transport Layer Protection' },
      { cwe: 'CWE-916', name: 'Use of Password Hash With Insufficient Computational Effort' }
    ]
  },
  'A03:2021': {
    name: 'Injection',
    cwes: [
      { cwe: 'CWE-20', name: 'Improper Input Validation' },
      { cwe: 'CWE-74', name: 'Improper Neutralization of Special Elements in Output Used by a Downstream Component (Injection)' },
      { cwe: 'CWE-75', name: 'Failure to Sanitize Special Elements into a Different Plane (Special Element Injection)' },
      { cwe: 'CWE-77', name: 'Improper Neutralization of Special Elements used in a Command (Command Injection)' },
      { cwe: 'CWE-78', name: 'Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)' },
      { cwe: 'CWE-79', name: 'Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)' },
      { cwe: 'CWE-80', name: 'Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)' },
      { cwe: 'CWE-83', name: 'Improper Neutralization of Script in Attributes in a Web Page' },
      { cwe: 'CWE-87', name: 'Improper Neutralization of Alternate XSS Syntax' },
      { cwe: 'CWE-88', name: 'Improper Neutralization of Argument Delimiters in a Command (Argument Injection)' },
      { cwe: 'CWE-89', name: 'Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)' },
      { cwe: 'CWE-90', name: 'Improper Neutralization of Special Elements used in an LDAP Query (LDAP Injection)' },
      { cwe: 'CWE-91', name: 'XML Injection (aka Blind XPath Injection)' },
      { cwe: 'CWE-93', name: 'Improper Neutralization of CRLF Sequences (CRLF Injection)' },
      { cwe: 'CWE-94', name: 'Improper Control of Generation of Code (Code Injection)' },
      { cwe: 'CWE-95', name: 'Improper Neutralization of Directives in Dynamically Evaluated Code (Eval Injection)' },
      { cwe: 'CWE-96', name: 'Improper Neutralization of Directives in Statically Saved Code (Static Code Injection)' },
      { cwe: 'CWE-97', name: 'Improper Neutralization of Server-Side Includes (SSI) Within a Web Page' },
      { cwe: 'CWE-98', name: 'Improper Control of Filename for Include/Require Statement in PHP Program (PHP Remote File Inclusion)' },
      { cwe: 'CWE-99', name: 'Improper Control of Resource Identifiers (Resource Injection)' },
      { cwe: 'CWE-100', name: 'Deprecated: Was catch-all for input validation issues' },
      { cwe: 'CWE-113', name: 'Improper Neutralization of CRLF Sequences in HTTP Headers (HTTP Response Splitting)' },
      { cwe: 'CWE-116', name: 'Improper Encoding or Escaping of Output' },
      { cwe: 'CWE-138', name: 'Improper Neutralization of Special Elements' },
      { cwe: 'CWE-184', name: 'Incomplete List of Disallowed Inputs' },
      { cwe: 'CWE-470', name: 'Use of Externally-Controlled Input to Select Classes or Code (Unsafe Reflection)' },
      { cwe: 'CWE-471', name: 'Modification of Assumed-Immutable Data (MAID)' },
      { cwe: 'CWE-564', name: 'SQL Injection: Hibernate' },
      { cwe: 'CWE-610', name: 'Externally Controlled Reference to a Resource in Another Sphere' },
      { cwe: 'CWE-643', name: 'Improper Neutralization of Data within XPath Expressions (XPath Injection)' },
      { cwe: 'CWE-644', name: 'Improper Neutralization of HTTP Headers for Scripting Syntax' },
      { cwe: 'CWE-652', name: 'Improper Neutralization of Data within XQuery Expressions (XQuery Injection)' },
      { cwe: 'CWE-917', name: 'Improper Neutralization of Special Elements used in an Expression Language Statement (Expression Language Injection)' }
    ]
  },
  'A04:2021': {
    name: 'Insecure Design',
    cwes: [
      { cwe: 'CWE-73', name: 'External Control of File Name or Path' },
      { cwe: 'CWE-183', name: 'Permissive List of Allowed Inputs' },
      { cwe: 'CWE-209', name: 'Generation of Error Message Containing Sensitive Information' },
      { cwe: 'CWE-213', name: 'Exposure of Sensitive Information Due to Incompatible Policies' },
      { cwe: 'CWE-235', name: 'Improper Handling of Extra Parameters' },
      { cwe: 'CWE-256', name: 'Unprotected Storage of Credentials' },
      { cwe: 'CWE-257', name: 'Storing Passwords in a Recoverable Format' },
      { cwe: 'CWE-266', name: 'Incorrect Privilege Assignment' },
      { cwe: 'CWE-269', name: 'Improper Privilege Management' },
      { cwe: 'CWE-280', name: 'Improper Handling of Insufficient Permissions or Privileges' },
      { cwe: 'CWE-311', name: 'Missing Encryption of Sensitive Data' },
      { cwe: 'CWE-312', name: 'Cleartext Storage of Sensitive Information' },
      { cwe: 'CWE-313', name: 'Cleartext Storage in a File or on Disk' },
      { cwe: 'CWE-316', name: 'Cleartext Storage of Sensitive Information in Memory' },
      { cwe: 'CWE-419', name: 'Unprotected Primary Channel' },
      { cwe: 'CWE-430', name: 'Deployment of Wrong Handler' },
      { cwe: 'CWE-434', name: 'Unrestricted Upload of File with Dangerous Type' },
      { cwe: 'CWE-444', name: 'Inconsistent Interpretation of HTTP Requests (HTTP Request Smuggling)' },
      { cwe: 'CWE-451', name: 'User Interface (UI) Misrepresentation of Critical Information' },
      { cwe: 'CWE-472', name: 'External Control of Assumed-Immutable Web Parameter' },
      { cwe: 'CWE-501', name: 'Trust Boundary Violation' },
      { cwe: 'CWE-522', name: 'Insufficiently Protected Credentials' },
      { cwe: 'CWE-525', name: 'Use of Web Browser Cache Containing Sensitive Information' },
      { cwe: 'CWE-539', name: 'Use of Persistent Cookies Containing Sensitive Information' },
      { cwe: 'CWE-579', name: 'J2EE Bad Practices: Non-serializable Object Stored in Session' },
      { cwe: 'CWE-598', name: 'Use of GET Request Method With Sensitive Query Strings' },
      { cwe: 'CWE-602', name: 'Client-Side Enforcement of Server-Side Security' },
      { cwe: 'CWE-642', name: 'External Control of Critical State Data' },
      { cwe: 'CWE-646', name: 'Reliance on File Name or Extension of Externally-Supplied File' },
      { cwe: 'CWE-650', name: 'Trusting HTTP Permission Methods on the Server Side' },
      { cwe: 'CWE-653', name: 'Insufficient Compartmentalization' },
      { cwe: 'CWE-656', name: 'Reliance on Security Through Obscurity' },
      { cwe: 'CWE-657', name: 'Violation of Secure Design Principles' },
      { cwe: 'CWE-799', name: 'Improper Control of Interaction Frequency' },
      { cwe: 'CWE-807', name: 'Reliance on Untrusted Inputs in a Security Decision' },
      { cwe: 'CWE-840', name: 'Business Logic Errors' },
      { cwe: 'CWE-841', name: 'Improper Enforcement of Behavioral Workflow' },
      { cwe: 'CWE-927', name: 'Use of Implicit Intent for Sensitive Communication' },
      { cwe: 'CWE-1021', name: 'Improper Restriction of Rendered UI Layers or Frames' },
      { cwe: 'CWE-1173', name: 'Improper Use of Validation Framework' }
    ]
  },
  'A05:2021': {
    name: 'Security Misconfiguration',
    cwes: [
      { cwe: 'CWE-2', name: '7PK - Environment' },
      { cwe: 'CWE-11', name: 'ASP.NET Misconfiguration: Creating Debug Binary' },
      { cwe: 'CWE-13', name: 'ASP.NET Misconfiguration: Password in Configuration File' },
      { cwe: 'CWE-15', name: 'External Control of System or Configuration Setting' },
      { cwe: 'CWE-16', name: 'Configuration' },
      { cwe: 'CWE-260', name: 'Password in Configuration File' },
      { cwe: 'CWE-315', name: 'Cleartext Storage of Sensitive Information in a Cookie' },
      { cwe: 'CWE-520', name: '.NET Misconfiguration: Use of Impersonation' },
      { cwe: 'CWE-526', name: 'Exposure of Sensitive Information Through Environmental Variables' },
      { cwe: 'CWE-537', name: 'Java Runtime Error Message Containing Sensitive Information' },
      { cwe: 'CWE-541', name: 'Inclusion of Sensitive Information in an Include File' },
      { cwe: 'CWE-547', name: 'Use of Hard-coded, Security-relevant Constants' },
      { cwe: 'CWE-611', name: 'Improper Restriction of XML External Entity Reference' },
      { cwe: 'CWE-614', name: 'Sensitive Cookie in HTTPS Session Without \'Secure\' Attribute' },
      { cwe: 'CWE-756', name: 'Missing Custom Error Page' },
      { cwe: 'CWE-776', name: 'Improper Restriction of Recursive Entity References in DTDs (XML Entity Expansion)' },
      { cwe: 'CWE-942', name: 'Permissive Cross-domain Policy with Untrusted Domains' },
      { cwe: 'CWE-1004', name: 'Sensitive Cookie Without \'HttpOnly\' Flag' },
      { cwe: 'CWE-1032', name: 'OWASP Top Ten 2017 Category A6 - Security Misconfiguration' },
      { cwe: 'CWE-1174', name: 'ASP.NET Misconfiguration: Improper Model Validation' }
    ]
  },
  'A06:2021': {
    name: 'Vulnerable and Outdated Components',
    cwes: [
      { cwe: 'CWE-937', name: 'OWASP Top 10 2013: Using Components with Known Vulnerabilities' },
      { cwe: 'CWE-1035', name: '2017 Top 10 A9: Using Components with Known Vulnerabilities' },
      { cwe: 'CWE-1104', name: 'Use of Unmaintained Third Party Components' }
    ]
  },
  'A07:2021': {
    name: 'Identification and Authentication Failures',
    cwes: [
      { cwe: 'CWE-255', name: 'Credentials Management Errors' },
      { cwe: 'CWE-259', name: 'Use of Hard-coded Password' },
      { cwe: 'CWE-287', name: 'Improper Authentication' },
      { cwe: 'CWE-288', name: 'Authentication Bypass Using an Alternate Path or Channel' },
      { cwe: 'CWE-290', name: 'Authentication Bypass by Spoofing' },
      { cwe: 'CWE-294', name: 'Authentication Bypass by Capture-replay' },
      { cwe: 'CWE-295', name: 'Improper Certificate Validation' },
      { cwe: 'CWE-297', name: 'Improper Validation of Certificate with Host Mismatch' },
      { cwe: 'CWE-300', name: 'Channel Accessible by Non-Endpoint' },
      { cwe: 'CWE-302', name: 'Authentication Bypass by Assumed-Immutable Data' },
      { cwe: 'CWE-304', name: 'Missing Critical Step in Authentication' },
      { cwe: 'CWE-306', name: 'Missing Authentication for Critical Function' },
      { cwe: 'CWE-307', name: 'Improper Restriction of Excessive Authentication Attempts' },
      { cwe: 'CWE-346', name: 'Origin Validation Error' },
      { cwe: 'CWE-384', name: 'Session Fixation' },
      { cwe: 'CWE-521', name: 'Weak Password Requirements' },
      { cwe: 'CWE-613', name: 'Insufficient Session Expiration' },
      { cwe: 'CWE-620', name: 'Unverified Password Change' },
      { cwe: 'CWE-640', name: 'Weak Password Recovery Mechanism for Forgotten Password' },
      { cwe: 'CWE-798', name: 'Use of Hard-coded Credentials' },
      { cwe: 'CWE-940', name: 'Improper Verification of Source of a Communication Channel' },
      { cwe: 'CWE-1216', name: 'Lockout Mechanism Errors' }
    ]
  },
  'A08:2021': {
    name: 'Software and Data Integrity Failures',
    cwes: [
      { cwe: 'CWE-345', name: 'Insufficient Verification of Data Authenticity' },
      { cwe: 'CWE-353', name: 'Missing Support for Integrity Check' },
      { cwe: 'CWE-426', name: 'Untrusted Search Path' },
      { cwe: 'CWE-494', name: 'Download of Code Without Integrity Check' },
      { cwe: 'CWE-502', name: 'Deserialization of Untrusted Data' },
      { cwe: 'CWE-565', name: 'Reliance on Cookies without Validation and Integrity Checking' },
      { cwe: 'CWE-784', name: 'Reliance on Cookies without Validation and Integrity Checking in a Security Decision' },
      { cwe: 'CWE-829', name: 'Inclusion of Functionality from Untrusted Control Sphere' },
      { cwe: 'CWE-830', name: 'Inclusion of Web Functionality from an Untrusted Source' },
      { cwe: 'CWE-915', name: 'Improperly Controlled Modification of Dynamically-Determined Object Attributes' }
    ]
  },
  'A09:2021': {
    name: 'Security Logging and Monitoring Failures',
    cwes: [
      { cwe: 'CWE-117', name: 'Improper Output Neutralization for Logs' },
      { cwe: 'CWE-223', name: 'Omission of Security-relevant Information' },
      { cwe: 'CWE-532', name: 'Insertion of Sensitive Information into Log File' },
      { cwe: 'CWE-778', name: 'Insufficient Logging' }
    ]
  },
  'A10:2021': {
    name: 'Server-Side Request Forgery (SSRF)',
    cwes: [
      { cwe: 'CWE-918', name: 'Server-Side Request Forgery (SSRF)' }
    ]
  }
};

/**
 * SANS Top 25 CWE mappings
 */
export const SANS_TOP_25_MAPPINGS = {
  1: { cwe: 'CWE-787', name: 'Out-of-bounds Write' },
  2: { cwe: 'CWE-79', name: 'Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)' },
  3: { cwe: 'CWE-89', name: 'Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)' },
  4: { cwe: 'CWE-416', name: 'Use After Free' },
  5: { cwe: 'CWE-78', name: 'Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)' },
  6: { cwe: 'CWE-20', name: 'Improper Input Validation' },
  7: { cwe: 'CWE-125', name: 'Out-of-bounds Read' },
  8: { cwe: 'CWE-22', name: 'Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)' },
  9: { cwe: 'CWE-352', name: 'Cross-Site Request Forgery (CSRF)' },
  10: { cwe: 'CWE-434', name: 'Unrestricted Upload of File with Dangerous Type' },
  11: { cwe: 'CWE-862', name: 'Missing Authorization' },
  12: { cwe: 'CWE-476', name: 'NULL Pointer Dereference' },
  13: { cwe: 'CWE-287', name: 'Improper Authentication' },
  14: { cwe: 'CWE-190', name: 'Integer Overflow or Wraparound' },
  15: { cwe: 'CWE-502', name: 'Deserialization of Untrusted Data' },
  16: { cwe: 'CWE-77', name: 'Improper Neutralization of Special Elements used in a Command (Command Injection)' },
  17: { cwe: 'CWE-119', name: 'Improper Restriction of Operations within the Bounds of a Memory Buffer' },
  18: { cwe: 'CWE-798', name: 'Use of Hard-coded Credentials' },
  19: { cwe: 'CWE-918', name: 'Server-Side Request Forgery (SSRF)' },
  20: { cwe: 'CWE-306', name: 'Missing Authentication for Critical Function' },
  21: { cwe: 'CWE-362', name: 'Concurrent Execution using Shared Resource with Improper Synchronization (Race Condition)' },
  22: { cwe: 'CWE-269', name: 'Improper Privilege Management' },
  23: { cwe: 'CWE-94', name: 'Improper Control of Generation of Code (Code Injection)' },
  24: { cwe: 'CWE-863', name: 'Incorrect Authorization' },
  25: { cwe: 'CWE-276', name: 'Incorrect Default Permissions' }
};

/**
 * MITRE Top 10 KEV mappings
 */
export const MITRE_KEV_MAPPINGS = {
  1: { cwe: 'CWE-787', name: 'Out-of-bounds Write', score: 75.59, cves: 18 },
  2: { cwe: 'CWE-843', name: 'Access of Resource Using Incompatible Type (Type Confusion)', score: 24.91, cves: 6 },
  3: { cwe: 'CWE-78', name: 'Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)', score: 24.27, cves: 6 },
  4: { cwe: 'CWE-94', name: 'Improper Control of Generation of Code (Code Injection)', score: 23.64, cves: 7 },
  5: { cwe: 'CWE-502', name: 'Deserialization of Untrusted Data', score: 23.07, cves: 5 },
  6: { cwe: 'CWE-22', name: 'Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)', score: 19.52, cves: 5 },
  7: { cwe: 'CWE-306', name: 'Missing Authentication for Critical Function', score: 17.60, cves: 6 },
  8: { cwe: 'CWE-89', name: 'Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)', score: 15.62, cves: 4 },
  9: { cwe: 'CWE-416', name: 'Use After Free', score: 15.43, cves: 5 },
  10: { cwe: 'CWE-77', name: 'Improper Neutralization of Special Elements used in a Command (Command Injection)', score: 14.90, cves: 4 }
};
