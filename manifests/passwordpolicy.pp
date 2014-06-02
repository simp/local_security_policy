define local_security_policy::passwordpolicy (
  $policy = $title,
  $setting,
) {
  include local_security_policy::maps::passwordpolicy

  # Fail logic
  $mapping = $local_security_policy::maps::passwordpolicy::Map[$policy]
  if !$mapping { fail("managing $policy not yet implemented") }


  $policyname = $mapping['name']

  #notify {"Policy: ${policyname}":}
  ## Template uses:
  #   - $mapping
  #   - $setting
  exec { "$policy password policy assignment":
    command  => template('local_security_policy/passwordpolicy_set.ps1.erb'),
    unless   => template('local_security_policy/passwordpolicy_check.ps1.erb'),
    provider => powershell,
  }

}
