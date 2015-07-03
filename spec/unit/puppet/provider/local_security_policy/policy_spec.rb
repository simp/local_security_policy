require 'spec_helper'
provider_class = Puppet::Type.type(:local_security_policy).provider(:policy)

describe provider_class do
  subject { provider_class }
  before :all do
    Puppet::Util.stubs(:which).with("wmic").returns("c:\\tools\\wmic")
    Puppet::Util.stubs(:which).with("secedit").returns("c:\\tools\\secedit")
  end
  before :each do
    infout = StringIO.new
    sdbout = StringIO.new
    allow(security_policy).to receive(:wmic).with([ "useraccount", "get", "name,sid", "/format:csv"]).and_return(File.read(userdata))
    allow(security_policy).to receive(:wmic).with([ "group", "get", "name,sid", "/format:csv"]).and_return(File.read(groupdata))
    allow(Tempfile).to receive(:new).with('infimport').and_return(infout)
    allow(Tempfile).to receive(:new).with('sdbimport').and_return(sdbout)
    allow(File).to receive(:file?).with(secdata).and_return(true)
    # the below mock seems to be required or rspec complains
    allow(File).to receive(:file?).with(/facter/).and_return(true)
    allow(subject).to receive(:temp_file).and_return(secdata)
    subject.stubs(:wmic).with([ "useraccount", "get", "name,sid", "/format:csv"]).returns(File.read(userdata))
    subject.stubs(:wmic).with([ "group", "get", "name,sid", "/format:csv"]).returns(File.read(groupdata))
    subject.stubs(:secedit).with(['/configure', '/db', 'sdbout', '/cfg', 'infout', '/quiet'])
    subject.stubs(:secedit).with(['/export', '/cfg', secdata, '/quiet'])

  end

  let(:security_policy){
    SecurityPolicy.new
  }

  # mock up the data which was gathered on a real windows system
  let(:secdata) do
    File.join(fixtures_path, 'unit', 'secedit.inf')
  end

  let(:groupdata) do
    File.join(fixtures_path, 'unit', 'group.txt')
  end

  let(:userdata) do
    File.join(fixtures_path, 'unit', 'useraccount.txt')
  end

  let(:facts)do {:is_virtual => 'false', :operatingsystem => 'windows'} end

  let(:resource) {
    Puppet::Type.type(:local_security_policy).new(
        :name => 'Network access: Let Everyone permissions apply to anonymous users',
        :ensure => 'present',
        :policy_setting => 'MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous',
        :policy_type    => 'Registry Values',
        :policy_value   => '0')
  }
  let(:provider) {
    provider_class.new(resource)
  }

  xit 'should create instances without error' do
    instances = provider_class.instances
    expect(instances.class).to eq(Array)
    expect(instances.count).to eq(94)
  end

  describe 'resource is removed' do
    let(:resource) {
      Puppet::Type.type(:local_security_policy).new(
          :name => 'Network access: Let Everyone permissions apply to anonymous users',
          :ensure => 'absent',
          :policy_setting => 'MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous',
          :policy_type    => 'Registry Values',
          :policy_value   => '0')
    }
    xit 'exists? should be true' do
      expect(provider.exists?).to eq(false)
      # until we can implement the destroy functionality this test is useless
      #expect(provider).to receive(:destroy).exactly(1).times
    end
  end

  describe 'resource is present' do
    let(:resource) {
      Puppet::Type.type(:local_security_policy).new(
          :name => 'Network access: Let Everyone permissions apply to anonymous users',
          :ensure => 'present',
          :policy_setting => 'MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous',
          :policy_type    => 'Registry Values',
          :policy_value   => '0')
    }
    xit 'exists? should be true' do
      expect(provider.exists?).to eq(true)
      expect(provider).to receive(:create).exactly(0).times
    end
  end

  describe 'resource is absent' do
    let(:resource) {
      Puppet::Type.type(:local_security_policy).new(
          :name => 'Network access: Let Everyone permissions apply to anonymous users',
          :ensure => 'present',
          :policy_setting => 'MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous',
          :policy_type    => 'Registry Values',
          :policy_value   => '3')
    }
    xit 'exists? should be false' do
      expect(provider.exists?).to eq(false)
      allow(provider).to receive(:create).exactly(1).times

    end
  end

  it "should be an instance of Puppet::Type::Local_security_policy::ProviderPolicy" do
    expect(provider).to be_an_instance_of Puppet::Type::Local_security_policy::ProviderPolicy
  end
end
