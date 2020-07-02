# frozen_string_literal: true

require 'spec_helper_acceptance'

describe 'local_security_policy' do
  context 'default parameters' do
    let(:manifest) { 'include local_security_policy' }

    it 'is expected to apply with no errors' do
      # Run twice to test idempotency
      apply_manifest(manifest, 'catch_failures' => true)
      apply_manifest(manifest, 'catch_changes' => true)
    end
  end
end
