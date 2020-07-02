# frozen_string_literal: true

require 'spec_helper'
require 'puppet_x/lsp/security_policy'

# rubocop:disable RSpec/SubjectStub,RSpec/NamedSubject,RSpec/AnyInstance
describe 'SecurityPolicy' do
  include PuppetlabsSpec::Fixtures

  subject { SecurityPolicy }

  before(:each) do
    ENV['COMPUTERNAME'] = 'testsystem'
    allow(Puppet::Util).to receive(:which).with('wmic').and_return('c:\\tools\\wmic')
    allow(Puppet::Util).to receive(:which).with('secedit').and_return('c:\\tools\\secedit')

    infout = StringIO.new
    sdbout = StringIO.new
    allow(Tempfile).to receive(:new).with('infimport').and_return(infout)
    allow(Tempfile).to receive(:new).with('sdbimport').and_return(sdbout)
    allow(File).to receive(:file?).with(secdata).and_return(true)
    # the below mock seems to be required or rspec complains
    allow(File).to receive(:file?).with(%r{facter|lsb_release}).and_return(true)
    allow(subject).to receive(:temp_file).and_return(secdata)
    allow(security_policy).to receive(:wmic).with(['useraccount', 'get', 'name,sid', '/format:csv']).and_return(userdata)
    allow(security_policy).to receive(:wmic).with(['group', 'get', 'name,sid', '/format:csv']).and_return(groupdata)
    allow_any_instance_of(SecurityPolicy).to receive(:wmic).with(['useraccount', 'where', '(domain="testsystem")', 'get', 'name,sid', '/format:csv']).and_return(userdata)
    allow_any_instance_of(SecurityPolicy).to receive(:wmic).with(['group', 'where', '(domain="testsystem")', 'get', 'name,sid', '/format:csv']).and_return(groupdata)

    allow(subject).to receive(:secedit).with(['/configure', '/db', 'sdbout', '/cfg', 'infout', '/quiet']).and_return(true)
    allow(subject).to receive(:secedit).with(['/export', '/cfg', secdata, '/quiet']).and_return(true)
  end

  let(:secdata) do
    my_fixture(File.join('..', 'secedit.inf'))
  end

  let(:groupdata) do
    file = my_fixture(File.join('..', 'group.txt'))
    File.open(file, 'r') { |f| f.read.encode('utf-8', universal_newline: true).delete("\xEF\xBB\xBF") }
  end

  let(:userdata) do
    file = my_fixture(File.join('..', 'useraccount.txt'))
    File.open(file, 'r') { |f| f.read.encode('utf-8', universal_newline: true).delete("\xEF\xBB\xBF") }
  end

  let(:security_policy) do
    SecurityPolicy.new
  end

  it 'returns builtin accounts' do
    # we just want to check that this is an array within an array that has 3 elements in each element
    expect(security_policy.builtin_accounts.count).to be > 50
    expect(security_policy.builtin_accounts.first.count).to eq(3)
  end

  it 'user_sid_array should return array' do
    a = security_policy.user_sid_array
    # we just want to check that this is an array within an array that has 3 elements in each element
    expect(a.count).to be > 50
    expect(a.first.count).to eq(3)
  end

  it 'local accounts should return array' do
    a = security_policy.local_accounts
    expect(a).to be_instance_of(Array)
    expect(a.count).to eq(19)
    expect(a.first.count).to eq(3)
  end

  it 'returns user' do
    expect(security_policy.sid_to_user('S-1-5-32-556')).to eq('Network Configuration Operators')
    expect(security_policy.sid_to_user('*S-1-5-80-0')).to eq('NT_SERVICE\\ALL_SERVICES')
  end

  it 'returns sid when user is not found' do
    expect(security_policy.user_to_sid('*S-11-5-80-0')).to eq('*S-11-5-80-0')
  end

  it 'returns sid' do
    expect(security_policy.user_to_sid('Network Configuration Operators')).to eq('*S-1-5-32-556')
    expect(security_policy.user_to_sid('NT_SERVICE\\ALL_SERVICES')).to eq('*S-1-5-80-0')
  end

  it 'returns user when sid is not found' do
    expect(security_policy.user_to_sid('N_SERVICE\\ALL_SERVICES')).to eq('N_SERVICE\\ALL_SERVICES')
  end

  describe 'registry value' do
    let(:resource) do
      Puppet::Type.type(:local_security_policy).new(
        name: 'Network access: Let Everyone permissions apply to anonymous users',
        ensure: 'present',
        policy_setting: 'MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous',
        policy_type: 'Registry Values',
        policy_value: '3',
      )
    end

    it 'converts a registry value' do
      expect(subject.convert_registry_value('Network access: Let Everyone permissions apply to anonymous users',
                                            3)).to eq('4,3')
    end

    it 'converts a policy right' do
      defined_policy = {
        name: 'Network access: Let Everyone permissions apply to anonymous users',
        ensure: 'present',
        policy_setting: 'MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous',
        policy_type: 'Registry Values',
        policy_value: '3',
      }
      hash = security_policy.convert_policy_hash(defined_policy)
      expect(hash[:policy_value]).to eq('4,3')
    end
  end

  describe 'privilege right' do
    let(:resource) do
      Puppet::Type.type(:local_security_policy).new(
        name: 'Access this computer from the network',
        ensure: 'present',
        policy_setting: 'SeNetworkLogonRight',
        policy_type: 'Privilege Rights',
        policy_value: 'AUTHENTICATED_USERS,BUILTIN_ADMINISTRATORS',
      )
    end

    it 'converts a privilege right to sids' do
      hash = security_policy.convert_policy_hash(resource)
      expect(hash[:policy_value]).to eq('*S-1-5-11,*S-1-5-32-544')
    end
  end

  # describe 'audit event' do
  #   let(:resource) {
  #     Puppet::Type.type(:local_security_policy).new(
  #         :name => 'Audit account logon events',
  #         :ensure         => 'present',
  #         :policy_setting => "AuditAccountLogon",
  #         :policy_type    => "Event Audit",
  #         :policy_value   => 'Success,Failure',
  #     )
  #   }
  #   it 'should convert a audit right' do
  #     defined_policy = SecurityPolicy.find_mapping_from_policy_desc(resource[:name])
  #     defined_policy.merge!(resource.to_hash)
  #     expect(provider.convert_audit(defined_policy)).to eq(3)
  #   end
  #
  #   it 'should convert a audit right' do
  #     defined_policy = SecurityPolicy.find_mapping_from_policy_desc(resource[:name])
  #     defined_policy.merge!(resource.to_hash)
  #     hash = provider.convert_policy_hash(defined_policy)
  #     expect(hash[:policy_value]).to eq(3)
  #   end
  # end
end
