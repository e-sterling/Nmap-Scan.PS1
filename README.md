# Nmap-Scan.PS1
PowerShell wrapper for nmap, allows easy scanning of many hosts and subnets

## Description 
Ingests a list of host names, IP addresses and/or sub nets and launches an nmap scan
against each one in sequence. Can be fed multiple text files either through
FileInfo objects or on the pipeline. Output is sent to an XML file in the format of
\[Host or subnet].xml in the current working dir. 

By default will use reasonable sane nmap arguments (-sT -T3) but custom arguments
can be specified using the parameter *-Arguments \[args]*

If the nmap executable is not accessible from the PATH variable an alternative
location can be specified using the parameter *-Location \[nmap location]*

## Parameters
**InputObject**
Either 1) A string of host names/IP Addresses/Subnets OR
  2) One or more FileInfo objects representing text files

**Arguments**
Specifies the arguments that will be passed to nmap
  Default: -sT -T3

**Location**
The location of the nmap executable
  Defaults to "nmap" (assumes nmap directory is in the PATH)

## Examples
    dir *.txt | .\Nmap-Scan
    Get an object containing text files in working directory, read files
    and run nmap against each host specified in each file (one per line)
 
    .\Nmap-Scan 10.0.0.0/24 -Arguments "-T5 -A -sC -sS"
    Run nmap against a subnet with custom arguments
 
    .\Nmap-Scan "scanme.nmap.org,192.168.0.1"
    Run nmap against a set of hosts and/or subnets
    
    Get-ADComputer -Filter {Name -like "HostName"} | .\Nmap-Scan.PS1
    Run nmap against objects returned by Get-ADComputer
    
## TO-DO
* Validate that host/subnet is valid before starting nmap
* Ability to feed in CSV with additional metadata?
