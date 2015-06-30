require 'tempfile'

begin
  require "puppet_x/twp/inifile"
  require "puppet_x/lsp/security_policy"
rescue LoadError => detail
  require 'pathname' # JJM WORK_AROUND #14073
  module_base = Pathname.new(__FILE__).dirname
  require module_base + "../../../" + "puppet_x/twp/inifile.rb"
  require module_base + "../../../" + "puppet_x/lsp/security_policy.rb"
end

Puppet::Type.type(:local_security_policy).provide(:policy) do
  desc 'Puppet type that models the local security policy'

  #
  # TODO Finalize the registry key settings
  # TODO Add in registry value translation (ex: 1=enable 0=disable)
  # TODO Implement self.post_resource_eval (need to collect all resource updates the run secedit to make one call)
  # limit access to windows hosts only
  confine :osfamily => :windows
  # limit access to systems with these commands since this is the tools we need
  commands :wmic => 'wmic', :secedit => 'secedit'

  mk_resource_methods

  # returns an array of builtin users and configured local users
  def self.user_sid_array
    @user_sid_array ||= local_accounts + SecurityPolicy.builtin_accounts
  end

  def self.user_to_sid(value)
    sid = user_sid_array.select{ |home,user,sid| user.match(/^#{value}$/)}
    if sid.nil? or sid.empty?
      sid = value
    else
      sid = '*' + sid[0][2]
    end
    sid
  end

  # convert the sid to a user
  def self.sid_to_user(value)
    value.gsub!(/(^\*)/ , '')
    user = user_sid_array.select { |home,user,sid| sid.match(/^#{value}$/)}
    if user.nil? or user.empty?
      user = value
    else
      user = user[0][1]
    end
    user
  end

  # collect all the local accounts using wmic
  def self.local_accounts
    ary = []
    ["useraccount","group"].each do |lu|
      wmic([lu,'get', 'name,sid', '/format:csv']).split("\n").each do |line|
        if line.include? ","
          ary << line.strip.split(",")
        end
      end
    end
    ary
  end

  # export the policy settings to the specified file and return the filename
  def self.export_policy_settings(inffile=temp_file)
    secedit(['/export', '/cfg', inffile, '/quiet'])
    inffile
  end

  # export and then read the policy settings from a file into a inifile object
  def self.read_policy_settings(inffile=temp_file)
    export_policy_settings(inffile)
    PuppetX::IniFile.load(inffile)
  end

  # exports the current list of policies into a file and then parses that file into
  # provider instances.  If an item is found on the system but not in the lsp_mapping,
  # that policy is not supported only because we cannot match the description
  def self.find_policy_settings
    settings = []
    inf = read_policy_settings
    # need to find the policy, section_header, policy_setting, policy_value and reg_type
    inf.each do |section, parameter_name, parameter_value|
      next if section == 'Unicode'
      next if section == 'Version'
      begin
        policy_desc, policy_values = SecurityPolicy::find_mapping_from_policy_name(parameter_name)
        settings << new(:name => policy_desc,
                        :ensure => :present,
                        :provider => :policy,
                        :policy_type => section ,
                        :policy_setting => parameter_name,
                        :policy_value => parameter_value,
                        :reg_type => policy_values[:reg_type])
      rescue KeyError => e
        # Log message goes here
        # Puppet::Verbose e.message
      end
    end
    settings
  end

  # find all the instances of this provider and type
  def self.instances
    self.find_policy_settings
  end

  def initialize(value={})
    super(value)
  end

  # create the resource and convert any user supplied values to computer terms
  def create
    begin
      defined_policy = SecurityPolicy.find_mapping_from_policy_desc(resource[:name])
      # merging the values here will take any default values form the mapping and the resource will override any values
      defined_policy.merge!(resource.to_hash)
      write_policy_to_system(defined_policy)
    rescue KeyError => e
      raise e.message
      # send helpful debug message to user here
    end
  end

  # this is currently not implemented correctly on purpose until we can figure out how to safely remove
  def destroy
    @property_hash[:ensure] = :absent
    #Destroy not an option for now.  LSP Settings should be set to something.
    # we need some default destroy values in the mappings so we know ahead of time what to put unless the user supplies
    # but this would just ensure a value the setting should go back to
  end

  def self.prefetch(resources)
    instances.each do |prov|
      if resource = resources[prov.name]
        resource.provider = prov
      end
    end
  end

  # check if the resource exists on a system already
  def exists?
    begin
      defined_policy = SecurityPolicy.find_mapping_from_policy_desc(resource[:name])
      defined_policy.merge!(resource.to_hash)
      # the incoming defined policy is user friends so we need to convert it computer lingo
      defined_policy = convert_policy_hash(defined_policy)
    rescue KeyError => e
      raise e.message
    end

    # we need to compare the hashes, however, the resource hash has a few keys we dont' care about
    # which precludes us from comparing hashes directly so I went ahead a compared almost all the keys manually via
    # conditionals.
    self.class.instances.each do | instance|
      inst = instance.to_hash
      if inst[:policy_type] == defined_policy[:policy_type] && inst[:name] == defined_policy[:name]
        if inst[:policy_value] == defined_policy[:policy_value] && inst[:policy_setting] == defined_policy[:policy_setting]
          if inst[:ensure] == defined_policy[:ensure]
            return true
          end
        end
      end
    end
    false
  end

  # gets the property hash from the provider
  def to_hash
    instance_variable_get('@property_hash')
  end

  # required for easier mocking, this could be a Tempfile too
  def self.temp_file
    'c:\\windows\\temp\\secedit.inf'
  end

  private


  def convert_privilege_right(policy_hash)
    # we need to convert users to sids first
    if policy_hash[:ensure] == :absent
      pv = ''
    else
      sids = Array.new
      policy_hash[:policy_value].split(",").sort.each do |suser|
        suser.strip!
        sids << user_to_sid(suser)
      end
      pv = sids.join(",")
    end
  end

  # converts the policy has and returns the policy value for audit types
  def convert_audit(policy_hash)
    return policy_hash[:policy_value] if policy_hash[:policy_value].instance_of?(Fixnum)
    if policy_hash[:policy_value] == 'No auditing'
      pv = 0
    else
      pv = 0
      policy_hash[:policy_value].split(",").split do |ssetting|
        if setting.strip! == 'Success'
          pv += 1
        elsif setting.strip! == 'Failure'
          pv += 2
        end
      end
    end
  end

  def convert_registry_value(policy_hash)
    "#{policy_hash[:reg_type]},#{policy_hash[:policy_value]}"
  end

  # converts the policy value inside the policy hash to confirm to the secedit standards
  def convert_policy_hash(policy_hash)
    case policy_hash[:policy_type]
      when 'Privilege Rights'
        value = convert_audit(policy_hash)
      when 'Event Audit'
        value = convert_audit(policy_hash)
      when 'Registry Values'
        value = convert_registry_value(policy_hash)
      else
        value = policy_hash[:policy_value]
    end
    policy_hash[:policy_value] = value
    policy_hash
  end

  # writes out one policy at a time using the InfFile Class and secedit
  def write_policy_to_system(policy_hash)
    infout = Tempfile.new('infimport')
    sdbout = Tempfile.new('sdbimport')
    begin
      # read the system state into the inifile object for easy variable setting
      inf = PuppetX::IniFile.new
      # these sections need to be here by default
      inf["Version"] = {"signature"=>"$CHICAGO$", "Revision"=>1}
      inf["Unicode"] = {"Unicode"=>"yes"}
      section = policy_hash[:policy_type]
      policy_hash = convert_policy_hash(policy_hash)
      section_value = {policy_hash[:policy_setting] => policy_hash[:policy_value]}
      # we can utilize the IniFile class to write out the data in ini format
      inf[section] = section_value
      inf.write(:filename => infout)
      secedit(['/configure', '/db', sdbout, '/cfg', infout, '/quiet'])
    ensure
      infout.close
      sdbout.close
      infout.unlink   # deletes the temp file
      sdbout.unlink
      File.rm(temp_file)
    end
  end
end