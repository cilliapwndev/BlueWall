# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name          = "bluewall"
  spec.version       = "1.0.0"
  spec.authors       = ["Mark Angelo P. Santonil"]
  spec.email         = ["cillia@gmail.com"] 
  spec.summary       = "A powerful firewall configuration auditor for pfSense and OpenSense."
  spec.description   = <<-DESC
    BlueWall is a security auditing tool that analyzes pfSense and OpenSense firewall configurations.
    It identifies security strengths and weaknesses, simulates attack scenarios, and provides a detailed
    compliance assessment against major security frameworks like NIST, CIS, and PCI DSS.
  DESC
  spec.homepage      = "https://github.com/cilliapwndev/bluewall" 
  spec.license       = "MIT"
  spec.required_ruby_version = Gem::Requirement.new(">= 2.6.0")

  spec.files         = Dir["lib/**/*.rb", "bin/*", "README.md", "LICENSE"]
  spec.bindir        = "bin"
  spec.executables   = ["bluewall"] 
  spec.require_paths = ["lib"]

  # Dependencies
  spec.add_runtime_dependency "nokogiri", "~> 1.15"
  spec.add_runtime_dependency "json", ">= 2.0"

  spec.metadata["allowed_push_host"] = "https://rubygems.org"
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"
end