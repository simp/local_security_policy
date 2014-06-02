define local_security_policy::userrights (
  $policy = $title,
  $setting,
) {
  include local_security_policy::maps::userrights

  # Fail logic
  $mapping = $local_security_policy::maps::userrights::Map[$policy]
  if !$mapping { fail("managing $policy not yet implemented") }


  $policyname = $mapping['name']

  notify {"Policy: ${policyname}":}
  ## Template uses:
  #   - $mapping
  #   - $setting
  exec { "$policy user rights assignment":
    command  => template('local_security_policy/userrights_set.ps1.erb'),
    unless   => template('local_security_policy/userrights_check.ps1.erb'),
    provider => powershell,
  }

}
