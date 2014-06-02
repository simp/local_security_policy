class local_security_policy::maps::passwordpolicy {

  $Map = {
    'Enforce password history' => {
      name => 'PasswordHistorySize',
      type => 'System Access',
    },
    'Maximum password age' => {
      name => 'MaximumPasswordAge',
      type => 'System Access',
    },
    'Minimum password age' => {
      name => 'MinimumPasswordLength',
      type => 'System Access',
    },
    'Minimum password length' => {
      name => 'MinimumPasswordLength',
      type => 'System Access',
    },
    'Password must meet complexity requirements' => {
      name => 'PasswordComplexity',
      type => 'System Access',
    },
  }

}
