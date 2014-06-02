class local_security_policy  {
	local_security_policy::userrights { "Allow log on locally":
		setting => ['Administrators', 'Users','Backup Operators'],
	}
}
