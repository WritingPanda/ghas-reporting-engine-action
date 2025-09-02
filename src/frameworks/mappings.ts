/**
 * OWASP Top 10 2021 CWE mappings
 */
export const OWASP_TOP_10_MAPPINGS = {
  'A01:2021': {
    name: 'Broken Access Control',
    cwes: [
      'CWE-22', 'CWE-23', 'CWE-35', 'CWE-59', 'CWE-200', 'CWE-201', 'CWE-219', 'CWE-264',
      'CWE-275', 'CWE-276', 'CWE-284', 'CWE-285', 'CWE-352', 'CWE-359', 'CWE-377', 'CWE-402',
      'CWE-425', 'CWE-441', 'CWE-497', 'CWE-538', 'CWE-540', 'CWE-548', 'CWE-552', 'CWE-566',
      'CWE-601', 'CWE-639', 'CWE-651', 'CWE-668', 'CWE-706', 'CWE-862', 'CWE-863', 'CWE-913',
      'CWE-922', 'CWE-1275'
    ]
  },
  'A02:2021': {
    name: 'Cryptographic Failures',
    cwes: [
      'CWE-259', 'CWE-261', 'CWE-296', 'CWE-310', 'CWE-319', 'CWE-321', 'CWE-322', 'CWE-323',
      'CWE-324', 'CWE-325', 'CWE-326', 'CWE-327', 'CWE-328', 'CWE-329', 'CWE-330', 'CWE-331',
      'CWE-335', 'CWE-336', 'CWE-337', 'CWE-338', 'CWE-340', 'CWE-347', 'CWE-523', 'CWE-720',
      'CWE-757', 'CWE-759', 'CWE-760', 'CWE-780', 'CWE-818', 'CWE-916'
    ]
  },
  'A03:2021': {
    name: 'Injection',
    cwes: [
      'CWE-20', 'CWE-74', 'CWE-75', 'CWE-77', 'CWE-78', 'CWE-79', 'CWE-80', 'CWE-83', 'CWE-87',
      'CWE-88', 'CWE-89', 'CWE-90', 'CWE-91', 'CWE-93', 'CWE-94', 'CWE-95', 'CWE-96', 'CWE-97',
      'CWE-98', 'CWE-99', 'CWE-100', 'CWE-113', 'CWE-116', 'CWE-138', 'CWE-184', 'CWE-470',
      'CWE-471', 'CWE-564', 'CWE-610', 'CWE-643', 'CWE-644', 'CWE-652', 'CWE-917'
    ]
  },
  'A04:2021': {
    name: 'Insecure Design',
    cwes: [
      'CWE-73', 'CWE-183', 'CWE-209', 'CWE-213', 'CWE-235', 'CWE-256', 'CWE-257', 'CWE-266',
      'CWE-269', 'CWE-280', 'CWE-311', 'CWE-312', 'CWE-313', 'CWE-316', 'CWE-419', 'CWE-430',
      'CWE-434', 'CWE-444', 'CWE-451', 'CWE-472', 'CWE-501', 'CWE-522', 'CWE-525', 'CWE-539',
      'CWE-579', 'CWE-598', 'CWE-602', 'CWE-642', 'CWE-646', 'CWE-650', 'CWE-653', 'CWE-656',
      'CWE-657', 'CWE-799', 'CWE-807', 'CWE-840', 'CWE-841', 'CWE-927', 'CWE-1021', 'CWE-1173'
    ]
  },
  'A05:2021': {
    name: 'Security Misconfiguration',
    cwes: [
      'CWE-2', 'CWE-11', 'CWE-13', 'CWE-15', 'CWE-16', 'CWE-260', 'CWE-315', 'CWE-520',
      'CWE-526', 'CWE-537', 'CWE-541', 'CWE-547', 'CWE-611', 'CWE-614', 'CWE-756', 'CWE-776',
      'CWE-942', 'CWE-1004', 'CWE-1032', 'CWE-1174'
    ]
  },
  'A06:2021': {
    name: 'Vulnerable and Outdated Components',
    cwes: ['CWE-937', 'CWE-1035', 'CWE-1104']
  },
  'A07:2021': {
    name: 'Identification and Authentication Failures',
    cwes: [
      'CWE-255', 'CWE-259', 'CWE-287', 'CWE-288', 'CWE-290', 'CWE-294', 'CWE-295', 'CWE-297',
      'CWE-300', 'CWE-302', 'CWE-304', 'CWE-306', 'CWE-307', 'CWE-346', 'CWE-384', 'CWE-521',
      'CWE-613', 'CWE-620', 'CWE-640', 'CWE-798', 'CWE-940', 'CWE-1216'
    ]
  },
  'A08:2021': {
    name: 'Software and Data Integrity Failures',
    cwes: [
      'CWE-345', 'CWE-353', 'CWE-426', 'CWE-494', 'CWE-502', 'CWE-565', 'CWE-784', 'CWE-829',
      'CWE-830', 'CWE-915'
    ]
  },
  'A09:2021': {
    name: 'Security Logging and Monitoring Failures',
    cwes: ['CWE-117', 'CWE-223', 'CWE-532', 'CWE-778']
  },
  'A10:2021': {
    name: 'Server-Side Request Forgery (SSRF)',
    cwes: ['CWE-918']
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
