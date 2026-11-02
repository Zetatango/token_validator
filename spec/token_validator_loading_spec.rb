# frozen_string_literal: true

require 'spec_helper'
require 'open3'

# Some of this library's constants are durations, evaluated when its files load. It must load the
# time helpers those need itself, rather than rely on a consumer having loaded them first. Run in a
# fresh process, because this suite has already loaded everything.
RSpec.describe TokenValidator do
  def load_in_fresh_process(script)
    Open3.capture2e(RbConfig.ruby, '-Ilib', '-e', script, chdir: File.expand_path('..', __dir__))
  end

  it 'loads with nothing required before it' do
    output, status = load_in_fresh_process("require 'token_validator'")

    expect(status).to be_success, output
  end

  it 'loads with only rails required before it' do
    output, status = load_in_fresh_process("require 'rails'; require 'token_validator'")

    expect(status).to be_success, output
  end
end
