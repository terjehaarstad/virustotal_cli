require 'rest-client'
require 'json'

#
# VirusTotal API v2 library
#
module VirusTotal
	class VirusTotalAPI
		# Initialize
		def initialize(verbose = false)
			@config = File.join(Dir.home, ".virustotal.conf")
			
			if not File.exists?(@config)
				puts "[!!] Config file #{@config} is not found!"
				exit
			end
			File.open(@config, "r") do |file|
				@key = file.gets.chomp
			end
			
			# check API key length here
			if @key.size < 64
				puts "[!!] API KEY ERROR!!"
				exit
			end
			$verbose = verbose
		end
		# Retrieve file-report  based on hashes (IE md5sum) from virustotal.com 
		def getFileReport(hash)
			response = RestClient.post(
				'https://www.virustotal.com/vtapi/v2/file/report',
				'resource' => hash,
				'apikey' => @key )
			JSON.parse(response)
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
				'https://www.virustotal.com/vtapi/v2/url/report',
				'resource' => url,
				'apikey' => @key )
			JSON.parse(response)
		end		
		# Upload file to virustotal.com
		def scanFile(filename)
			if File.exist?(filename)
				response = RestClient.post( 
					'https://www.virustotal.com/vtapi/v2/file/scan',
					'apikey' => @key, 
					'file' => File.open(filename, 'rb') )
				JSON.parse(response)
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
		def getMd5Sum(file)
			Digest::MD5.hexdigest(File.read(file))
		end
		
		#
		# Private API 
		# Not tested
		def getIPReport(ip)
			response = RestClient.get(
				'https://www.virustotal.com/vtapi/v2/ip-address/report',
				'ip' => ip,
				'apikey' => @key )
			JSON.parse(response)
		end
		def getDomainReport(domain)
			response = RestClient.get(
				'https://www.virustotal.com/vtapi/v2/domain/report',
				'domain' => domain,
				'apikey' => @key )
			JSON.parse(response)
		end
	end
end
