begin
  require "puppet_x/lsp/security_policy"
rescue LoadError => detail
  require 'pathname' # JJM WORK_AROUND #14073
  module_base = Pathname.new(__FILE__).dirname
  require module_base + "../../../" + "puppet_x/lsp/security_policy.rb"
end

Puppet::Type.newtype(:local_security_policy) do
  @doc = 'Puppet type that models the local security policy'

  ensurable

  def policy_utils
    @policy_utils ||= SecurityPolicy.new
  end

  newparam(:name, :namevar => true) do
    desc 'Local Security Setting Name. What you see it the GUI.'
    validate do |value|
      fail("Invalid Policy name: #{value}") unless SecurityPolicy.valid_lsp?(value)
    end
  end

  newproperty(:policy_type) do
    newvalues('System Access','Event Audit','Privilege Rights','Registry Values', nil, '' )
    desc 'Local Security Policy Machine Name.  What OS knows it by.'
    # uses the resource name to perform a lookup of the defined policy and returns the policy type
    munge do |value|
      begin
        policy_hash = SecurityPolicy.find_mapping_from_policy_desc(resource[:name])
        policy_hash[:policy_type]
      rescue KeyError => e
        fail(e.message)
      end
    end
  end

  newproperty(:policy_setting) do
    desc 'Local Security Policy Machine Name.  What OS knows it by.'
  end

  newproperty(:policy_value) do
    desc 'Local Security Policy Setting Value'
    validate do |value|
      case resource[:policy_type].to_s
        when 'Privilege Rights'
          # maybe validate some sort of user?
        when 'Event Audit'
          fail("Invalid Event type: #{value} for #{resource[:policy_value]}") unless SecurityPolicy::EVENT_TYPES.include?(value)
        when 'Registry Values'
          # maybe validate some sort of value somehow?
      end
    end

    munge do | value |
      # need to convert policy values to designated types
      case resource[:policy_type].to_s
        when 'Registry Values'
          # secedit values sometimes look like : "1,\"4\""
          value = value.gsub(/\"/,'')
      end
      SecurityPolicy.convert_policy_value(resource.to_hash, value)
    end
  end
end


