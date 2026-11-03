# frozen_string_literal: true

require 'spec_helper'
require 'open3'
require 'rbconfig'

# The library must load in a process that has required only what it names as its own dependencies,
# whatever else the host application happens to have loaded first.
RSpec.describe TokenValidator do
  def load_after(preamble)
    lib = File.expand_path('../../lib', __dir__)
    script = "#{preamble}; require 'token_validator'; print TokenValidator::AdditionalIssuerFetchHelper::FAILED_FETCH_BACKOFF.to_i"
    Open3.capture3(RbConfig.ruby, '-I', lib, '-e', script)
  end

  describe 'loading the library' do
    ["require 'rails'", "require 'rails'; require 'active_record'"].each do |preamble|
      it "succeeds after only: #{preamble}" do
        output, error, status = load_after(preamble)

        expect([status.success?, output, error.lines.first]).to eq([true, '10', nil])
      end
    end
  end
end
