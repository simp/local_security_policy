# puppet-local_security_policy

## Overview
Configure, local security policy for windows servers.  LSP is key to a baseline configuration of the following security features:
* Account Policy
** Password Policy
** Account Lockout Policy
* Local Policy
** Audit Policy
** User Rights Assignment
** Security Options
** Registry Values

The title and name of the resources is exact match of what is in secedit GUI

## Status


## Examples

* Show all local_security_policy resources available on server
puppet resource local_security_policy

* Show a single local_security_policy resources available on server
puppet resource local_security_policy 'Maximum password age'

* Example Password Policy
local_security_policy { 'Maximum password age':
  ensure => present,
  policy_value => '90',
}


* Example Audit Policy
local_security_policy { 'Audit account logon events':
  ensure => present,
  policy_value => 'Success,Failure',
}

* Example User Rights Policy
local_security_policy { 'Allow log on locally':
  ensure => present,
  policy_value => '90',
}

* Example Security Settings
local_security_policy { 'System cryptography: Use FIPS compiant algorithms for encryption, hashing, and signing':
  ensure => present,
  policy_value => 1 ,
}
