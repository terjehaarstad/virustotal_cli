require 'rest-client'
require 'json'

#
# VirusTotal API v2 library
#
class VirusTotal
	# Initialize
	def initialize(key, verbose = false)
		# check API key length here
		if key.size < 64
			puts "[!!] API KEY ERROR!!"
			exit
		end
		@key = key
		@verbose = verbose
	end
	# Retrieve file-report  based on hashes (IE md5sum) from virustotal.com 
	def getFileReport(hash)
		response = RestClient.post(
			'https://www.virustotal.com/vtapi/v2/file/report',
			'resource' => hash,
			'apikey' => @key )
		report = JSON.parse(response)
	end
	# Retrieve multiple file-reports from array (of hashes)
	def getFileReports(array)
		hashes = array
		# Get multiple file reports
		i = 0
		hashes = hashes.uniq
		while i < hashes.size
			4.times do
				if hashes == nil
					break
				else
					puts "[*] Fetching file report for #{hashes[i].slice(0)} (#{i+1}/#{hashes.size})"
					hashes[i] << VirusTotal.new.get_file_report(hashes[i].slice(0))
				end
			end
			i += 1
		end
		if i >= (hashes.size - 4)
			puts "[*] Skipping 4.times loop, i am all done.."
			return hashes
		else
			puts "[*] Sleeping 65 seconds."
			sleep(65)
		end
	end
	# Retrieve Url Report from Virustotal.com
	def getUrlReport(url)
		response = RestClient.post(
			'http://www.virustotal.com/vtapi/v2/url/report',
			'resource' => url,
			'apikey' => @key )
		report = JSON.parse(response)
	end
	# Upload file to virustotal.com
	def scanFile(filename)
		if File.exist?(filename)
			response = RestClient.post( 
				'https://www.virustotal.com/vtapi/v2/file/scan',
				'apikey' => @key, 
				'file' => File.open(filename, 'rb') )
			result = JSON.parse(response)
		else
			return "[!!] Could not open file #{filename}"
		end
	end
	# Let virustotal scan url to check for malicious content
	def scanUrl(url)
		response = RestClient.post(
			'https://www.virustotal.com/vtapi/v2/url/scan',
			'url' => url,
			'apikey' => @key )
		result = JSON.parse(response)
	end
	# Display Report retrieved from VirusTotal.com
	def displayReport(report)
		# From API documentation:
		# If the file was not present in our file store this code will be -1. 
		# In the event of some unexpected error the code will be fixed to 0.
		
		# Display Reports
		if report['response_code'] == 1
			puts "[+]-------------------------------------------------------------------------"
			puts "[*] Resource: #{report['resource']}"
			puts "[*] Link: #{report['permalink']}"
			puts "[*] MD5: #{report['md5']}"
			puts "[*] SHA256: #{report['sha256']}"
			puts "[*] Detection Ratio: #{report['positives']}/#{report['total']}"
			puts "[*] Scan date: #{report['scan_date']}"
			puts "[+]-------------------------------------------------------------------------"	
			if @verbose
				puts "[*] Report:"
				report['scans'].each do |key, value|
					puts " [R] #{key}: #{value['result']}"
				end
				puts "[+]-------------------------------------------------------------------------"	
			end
		else 
			puts "[!!] #{report['verbose_msg']}"
		end
	end
	# Write VirusTotal report to md5sum_filename....
	def writeReport(report)
		# Write file to filename // Check this, write to resource, not md5sum.
		filename = "#{report['md5']}.vt"
		if File.exists?(filename)
			puts "[!!] #{filename} exists, skipping --write option"
		elsif
			File.open(filename, 'w') do |file|
				file.puts "-------------------------------------------------------------------------"
				file.puts "[*] Resource: #{report['resource']}"
				file.puts "[*] Detection Ratio: #{report['positives']}/#{report['total']}"
				file.puts "[*] Link: #{report['permalink']}"
				file.puts "[*] MD5: #{report['md5']}"
				file.puts "-------------------------------------------------------------------------"
				# Print Virustotal.com results
				file.puts "[*] Report:"
				report['scans'].each do |key, value|
					file.puts "[R] #{key}: #{value['result']}"
				end
			end
		end
	end
	def getMd5Sum(file)
		Digest::MD5.hexdigest(File.read(file))
	end
end
