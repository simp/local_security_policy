# frozen_string_literal: true

require 'spec_helper_acceptance'

describe 'local_security_policy' do
  context 'unset event audit policy' do
    let(:manifest) do
      <<~END
        local_security_policy { 'Audit account logon events':
          ensure       => present,
          policy_value => 'No auditing',
        }
      END
    end

    it 'is expected to apply with no errors' do
      # Run twice to test idempotency
      apply_manifest(manifest, 'catch_failures' => true)
      apply_manifest(manifest, 'catch_changes' => true)
    end

    it 'sets the value correctly' do
      hosts.each do |host|
        value = on(host, 'auditpol /get /category:*')
        expect(value.output).to match(%r{^\s*Other Account Logon Events\s*No Auditing$})
      end
    end
  end

  context 'set event audit policy' do
    let(:manifest) do
      <<~END
        local_security_policy { 'Audit account logon events':
          ensure       => present,
          policy_value => 'Success,Failure',
        }
      END
    end

    it 'is expected to apply with no errors' do
      # Run twice to test idempotency
      apply_manifest(manifest, 'catch_failures' => true)
      apply_manifest(manifest, 'catch_changes' => true)
    end

    it 'sets the value correctly' do
      hosts.each do |host|
        value = on(host, 'auditpol /get /category:*')
        expect(value.output).to match(%r{^\s*Credential Validation\s*Success and Failure$})
      end
    end
  end
end
