#!/usr/bin/env ruby
$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '/../lib'))
require 'optparse'
require 'virustotal'


#
# Virustotal reports from CLI
#

class VT_CLI
	def initialize(userOpt)
		@debug = false
		@api_key = 'your key here'
		@config = File.join(Dir.home, ".virustotal.conf")
		
		if not File.exists?(@config)
			puts "[!!] Config file #{@config} is not found!"
		end
		File.open(@config, "r") do |file|
			@api_key = file.gets.chomp
		end
		
		
		# Arguments check
		if userOpt == nil
			puts parseOpt("--help")
		elsif
			parseOpt(userOpt)
			run
		end
	end
	def parseOpt(option)
		@options = {}
		@cmd = {}
		
		# Option Parser
		OptionParser.new do |opts|
			opts.banner = "Usage: #{$0} [OPTIONS] COMMAND RESOURCE"
			
			#Options
			opts.separator "Options:"
			opts.on('-h', '--help', "This screen") {puts opts}
			opts.on('-v', '--verbose', "Show complete report") {@options[:verbose] = true}
			
			# !! Doesnt work.
			#opts.on('-w', '--write', "Writes report to 'hash-filename.vt'")  {options[:write] = true}
			
			#Commands
			opts.separator "Commands:"
			opts.on('--scanfile [FILE]', 'Uploads a file to VT') do |file|
				@cmd[:scanfile] = file
			end
			opts.on('--scanurl [URL]', "Check url with VT") do |url|
				@cmd[:scanurl] = url
			end
			opts.on('--hash [HASH]', "Get Virustotal report from a hash(MD5/SHA)") do |hash|
				@cmd[:hash] = hash
			end
			opts.on('--file [FILE]', "Get Virustotal report from a file") do |file|
				@cmd[:file] = file
			end
			opts.on('--url [URL]', "Get Virustotal report from URL") do |url|
				@cmd[:url] = url
			end
			opts.parse!
		end
	end
	def run
		# Create VirusTotal object
		if @options[:verbose]
			@vt = VirusTotal.new(@api_key, @verbose = true)
		else
			@vt = VirusTotal.new(@api_key)
		end

		# Commands
		if @cmd[:hash]
			@vt.displayReport(@vt.getFileReport(@cmd[:hash]))
		elsif @cmd[:file]
			@vt.displayReport(@vt.getFileReport(@vt.getMd5Sum(@cmd[:file])))
		elsif @cmd[:url]
			@vt.displayReport(@vt.getUrlReport(@cmd[:url]))
			
		# Upload file / url to be tested @ VirusTotal.com
		elsif @cmd[:scanfile]
			print @vt.scanFile(@cmd[:scanfile])
		elsif @cmd[:scanurl]
			print @vt.scanUrl(@cmd[:scanurl])
		else
			puts parseOpt('--help')
			exit
		end
	end
end

VT_CLI.new(ARGV[0])
