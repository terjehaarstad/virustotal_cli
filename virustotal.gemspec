lib = File.expand_path('../lib/', __FILE__)
$:.unshift(lib) unless $:.include?(lib)

require 'virustotal'
Gem::Specification.new do |s|
	# Information
 	 s.name =  VirusTotal::APP_NAME
	 s.version = VirusTotal::VERSION
	 s.date = '2013-05-27'
	 s.summary = 'Virustotal requests from CLI'
	 s.description = "Handles virustotal API requests from linux terminal."
	 s.required_ruby_version = ">= 1.9.2"
	 s.author = 'Terje Haarstad'
	 s.has_rdoc = true
	# Files
	 s.files = Dir['lib/**/*'] + Dir['bin/*']
	 s.executables << 'vt_cli.rb'
	# Dependencies 
	 s.add_dependency('rest-client', '>= 1.6.7')
	 s.add_dependency('json', '>= 1.7.5')

end

