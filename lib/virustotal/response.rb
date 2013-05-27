module VirusTotal
	#
	# VirusTotal Report
	class Report
		attr_accessor :scans, :scan_id, :sha1, :resource, :response_code, :scan_date, :permalink, :verbose_msg, :total, :positives, :sha256, :md5
		
		def initialize(args = {})
			@scans = args["scans"]			# Returns a hash of scans / av-vendor results.
			@scan_id = args["scan_id"]
			@sha1 = args["sha1"]
			@resource  = args["resource"]
			@response_code = args["response_code"]
			@scan_date = args["scan_date"]
			@permalink = args["permalink"]
			@verbose_msg = args["verbose_msg"]
			@total = args["total"]
			@positives = args["positives"]
			@sha256= args["sha256"]
			@md5 = args["md5"]
		end
		
		#
		# Writes VT Response to a file with md5_sum.vt as filename in current working directory. 
		def write2file
			if gotResults?
				File.open((@md5+".vt"), 'w') do |file|
					file.puts "[+]-------------------------------------------------------------------------"
					file.puts "[*] Resource: #{@resource}"
					file.puts "[*] Link: #{@permalink}"
					file.puts "[*] MD5: #{@md5}"
					file.puts "[*] SHA1: #{@sha1}"
					file.puts "[*] SHA256: #{@sha256}"
					file.puts "[*] Detection Ratio: #{@positives}/#{@total}"
					file.puts "[*] Scan date: #{@scan_date}"
					file.puts "[+]-------------------------------------------------------------------------"	
					file.puts "[*] Report:"
					@scans.each do |key, value|
						file.puts " [R] #{key}: #{value['result']}"
					end
					file.puts "[+]-------------------------------------------------------------------------"	
				end
			end
		end
		#
		# Did we get any results on the VT request?
		def gotResults?
			# From API documentation:
			# If the file was not present in our file store this code will be -1. 
			# In the event of some unexpected error the code will be fixed to 0.
			
			if @response_code == 1
				return true 
			else
				puts "#{@verbose_msg}"
			end
		end
		def write2display
			if gotResults?
				puts "[+]-------------------------------------------------------------------------"
				puts "[*] Resource: #{@resource}"
				puts "[*] Link: #{@permalink}"
				puts "[*] MD5: #{@md5}"
				puts "[*] SHA1: #{@sha1}"
				puts "[*] SHA256: #{@sha256}"
				puts "[*] Detection Ratio: #{@positives}/#{@total}"
				puts "[*] Scan date: #{@scan_date}"
				puts "[+]-------------------------------------------------------------------------"	
				if @verbose	
					puts "[*] Report:"
					@scans.each do |key, value|
						puts " [R] #{key}: #{value['result']}"
					end
				end
				
				puts "[+]-------------------------------------------------------------------------"	
			end
		end
		def write2erb
		end
	end
	#
	# Response on scanned items.
	class ScanResponse
		attr_accessor :scan_id, :sha1, :resource, :response_code, :sha256, :permalink, :md5, :verbose_msg
		def initialize(args = {})
			@scan_id = args["scan_id"]
			@sha1 = args["sha1"]
			@resource  = args["resource"]
			@response_code = args["response_code"]
			@permalink = args["permalink"]
			@verbose_msg = args["verbose_msg"]
			@sha256= args["sha256"]
			@md5 = args["md5"]
		end
		def write2display
			puts "Scan ID: #{@scan_id}"
			puts "Link: #{@permalink}"
			puts "#{@verbose_msg}"
		end
	end
end