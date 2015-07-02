require 'spec_helper'
require "puppet_x/lsp/security_policy"

describe 'SecurityPolicy' do
  subject { SecurityPolicy }
  before :all do
    Puppet::Util.stubs(:which).with("wmic").returns("c:\\tools\\wmic")
    Puppet::Util.stubs(:which).with("secedit").returns("c:\\tools\\secedit")
  end
  before :each do
    infout = StringIO.new
    sdbout = StringIO.new
    allow(Tempfile).to receive(:new).with('infimport').and_return(infout)
    allow(Tempfile).to receive(:new).with('sdbimport').and_return(sdbout)
    allow(File).to receive(:file?).with(secdata).and_return(true)
    # the below mock seems to be required or rspec complains
    allow(File).to receive(:file?).with(/facter/).and_return(true)
    allow(subject).to receive(:temp_file).and_return(secdata)
    security_policy.stubs(:wmic).with([ "useraccount", "get", "name,sid", "/format:csv"]).returns(File.read(userdata))
    security_policy.stubs(:wmic).with([ "group", "get", "name,sid", "/format:csv"]).returns(File.read(groupdata))

    subject.stubs(:secedit).with(['/configure', '/db', 'sdbout', '/cfg', 'infout', '/quiet'])
    subject.stubs(:secedit).with(['/export', '/cfg', secdata, '/quiet'])
  end

  let(:secdata) do
    File.join(fixtures_path, 'unit', 'secedit.inf')
  end

  let(:groupdata) do
    File.join(fixtures_path, 'unit', 'group.txt')
  end

  let(:userdata) do
    File.join(fixtures_path, 'unit', 'useraccount.txt')
  end

  let(:security_policy){
    SecurityPolicy.new

  }
  it 'should return builtin accounts' do
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

  it 'should return user' do
    expect(security_policy.sid_to_user("S-1-5-32-556")).to eq('Network Configuration Operators')
    expect(security_policy.sid_to_user('*S-1-5-80-0')).to eq("NT_SERVICE\\ALL_SERVICES")
  end

  it 'should return sid when user is not found' do
    expect(security_policy.user_to_sid('*S-11-5-80-0')).to eq('*S-11-5-80-0')
  end

  it 'should return sid' do
    expect(security_policy.user_to_sid("Network Configuration Operators")).to eq('*S-1-5-32-556')
    expect(security_policy.user_to_sid("NT_SERVICE\\ALL_SERVICES")).to eq('*S-1-5-80-0')
  end

  it 'should return user when sid is not found' do
    expect(security_policy.user_to_sid("N_SERVICE\\ALL_SERVICES")).to eq("N_SERVICE\\ALL_SERVICES")
  end


end
