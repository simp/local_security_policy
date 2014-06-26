Puppet::Type.newtype(:local_security_policy) do
  #confine :operatinsystme => { :windows ]
  desc 'Pupet type that models the local'

  ensurable

  newparam(:name, :namevar => true) do
    desc 'Local Security Setting Name. What you see it the GUI.'
  end

  newproperty(:policy_type) do
    desc 'Local Security Policy Machine Name.  What OS knows it by.'
  end


  newproperty(:policy_setting) do
    desc 'Local Security Policy Machine Name.  What OS knows it by.'
  end

  newproperty(:policy_value) do
    desc 'Local Security Polciy Setting Value'
  end
end
