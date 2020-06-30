# frozen_string_literal: true

require 'spec_helper_acceptance'
require 'json'

def get_reg_key_on(host, key)
  powershell = 'powershell.exe -noprofile -nologo -noninteractive -command'
  ps = on host, %(#{powershell} "Get-ItemProperty -Path \\\"#{key}\\\" | ConvertTo-Json")
  JSON.parse(ps.stdout)
end

describe 'local_security_policy' do
  context 'enable registry value policy' do
    let(:manifest) do
      <<~END
        local_security_policy { 'System objects: Strengthen default permissions of internal system objects (e.g., Symbolic Links)':
          ensure       => present,
          policy_value => '4,1',
        }
      END
    end

    it 'applies with no errors' do
      # Run twice to test idempotency
      apply_manifest(manifest, 'catch_failures' => true)
      apply_manifest(manifest, 'catch_changes' => true)
    end

    it 'sets the value correctly' do
      hosts.each do |host|
        # value = get_registry_value_on(host, :hklm, 'SYSTEM\CurrentControlSet\Control\Session Manager', 'ProtectionMode')
        value = get_reg_key_on(host, 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager')
        expect(value['ProtectionMode']).to eq(1)
      end
    end
  end

  context 'disable registry value policy' do
    let(:manifest) do
      <<~END
        local_security_policy { 'System objects: Strengthen default permissions of internal system objects (e.g., Symbolic Links)':
          ensure       => present,
          policy_value => '4,0',
        }
      END
    end

    it 'applies with no errors' do
      # Run twice to test idempotency
      apply_manifest(manifest, 'catch_failures' => true)
      apply_manifest(manifest, 'catch_changes' => true)
    end

    it 'sets the value correctly' do
      hosts.each do |host|
        # value = get_registry_value_on(host, :hklm, 'SYSTEM\CurrentControlSet\Control\Session Manager', 'ProtectionMode')
        value = get_reg_key_on(host, 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager')
        expect(value['ProtectionMode']).to eq(0)
      end
    end
  end
end
