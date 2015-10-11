# DNA

The objectives of this project:
 1) Develop a research platform for network analysis
 2) Learn practical application of the Go language (http://golang.org)
 3) Using Go, capture network traffic
 4) Using Go and Redis, store network traffic on the redis server
 5) Deploy it on the GENI.net platform

 Library dependencies:
   fmt
   net
   log
   time
   github.com/google/gopacket
   github.com/google/gopacket/layers
   github.com/google/gopacket/pcap


File structure:
./main/driver.go				// main program entry, calls scanner.go
./scanner/scanner.go			// gives on option to read local pcap files, or monitor live raw network traffic (in promiscous mode)
./util/util.go					// simple util 
      /util_test.go

 Current progress:
 Google's PCAP library:
  + Able to capture PCAP files using Go lang.
  + Able to monitor live network traffic (need to run sudo command before calling main program)
  
