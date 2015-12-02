#!/usr/bin/env ruby
$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '/../lib'))
require 'optparse'
require 'virustotal'


#
# Virustotal reports from CLI
#
module VirusTotal
	class VT_CLI
		def initialize(userOpt)
			@debug = false
		
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
				opts.on('-F', '--scanfile [FILE]', 'Upload and scan [FILE]') do |file|
					@cmd[:scanfile] = file
				end
				opts.on('-U', '--scanurl [URL]', "Upload and scan [URL].") do |url|
					@cmd[:scanurl] = url
				end
				opts.on('-H', '--hash [HASH]', "Get report on [HASH] (MD5/SHA)") do |hash|
					@cmd[:hash] = hash
				end
				opts.on('-f', '--file [FILE]', "Get report on [FILE]") do |file|
					@cmd[:file] = file
				end
				opts.on('-u', '--url [URL]', "Get report on [URL]") do |url|
					@cmd[:url] = url
				end
				opts.parse!
			end
		end
		def run
			# Create VirusTotal object
			if @options[:verbose]
				@vt = VirusTotalAPI.new(@verbose = true)
			else
				@vt = VirusTotalAPI.new
			end

			# Commands
			if @cmd[:hash]
				@res = Report.new(@vt.getFileReport(@cmd[:hash]))
				@res.write2display
			elsif @cmd[:file]
				@res = Report.new(@vt.getFileReport(@vt.getMd5Sum(@cmd[:file])))
				@res.write2display
			elsif @cmd[:url]
				@res = Report.new(@vt.getUrlReport(@cmd[:url]))
				@res.write2display
			elsif @cmd[:scanfile]
				@res = ScanResponse.new(@vt.scanFile(@cmd[:scanfile]))
				@res.write2display
			elsif @cmd[:scanurl]
				@res = ScanResponse.new(@vt.scanUrl(@cmd[:scanurl]))
				@res.write2display
			else
				puts parseOpt('--help')
				exit
			end
		end
	end
end
include VirusTotal
VT_CLI.new(ARGV[0])
