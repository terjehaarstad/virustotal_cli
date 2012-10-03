Gem::Specification.new do |s|
	# Information
 	 s.name =  'virustotal'
	 s.version = '0.1'
	 s.date = '2012-08-20'
	 s.summary = 'Virustotal requests from CLI'
	 s.description = "Handles virustotal API requests from linux terminal."
	 s.required_ruby_version = ">= 1.9.2"
	 s.author = 'Terje Haarstad'
	# Files
	 s.files = Dir['lib/*.rb'] + Dir['bin/*']
	 s.executables << 'vt_cli.rb'
	# Dependencies 
	 s.add_dependency('rest-client', '>= 1.6.7')
	 s.add_dependency('json', '>= 1.7.5')

end

