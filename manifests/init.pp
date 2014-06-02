class local_security_policy  {
	local_security_policy::userrights { "Allow log on locally":
		setting => ['Administrators', 'Users' ],
	}
	local_security_policy::passwordpolicy { "Maximum password age":
		setting => "60",
	}
}
