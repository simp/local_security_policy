class local_security_policy::maps::userrights {

  $Map = {
    'Allow log on locally' => {
      name => 'SeInteractiveLogonRight',
      type => 'Privilege Rights',
    },
    'registry type policy' => {
      name         => 'machinename1',
      type         => 'registry',
      registrytype => '4',
    },
  }

}
