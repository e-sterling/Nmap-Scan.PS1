# Nmap-Scan.PS1
PowerShell wrapper for nmap, allows easy scanning of many hosts and subnets

## Description 
Ingests a list of host names, IP addresses and/or subnets and launches an nmap scan
against each one in sequence. Can be fed multiple plaintext or CSV files either
through FileInfo objects or on the pipeline. Can also be fed a string containing
targets in a comma-separated list, or ADComputer objects created by Get-ADComputer.

Output is sent to an XML file in the format of \[Host or subnet].xml in the
current working directory. 

By default will use reasonable sane nmap arguments (-sT -T3) but custom arguments
can be specified using the parameter *-Arguments \[args]*

If the nmap executable is not accessible from the PATH variable an alternative
location can be specified using the parameter *-Location \[nmap location]*

## Parameters
**InputObject**
Either 1) A string of host names/IP Addresses/Subnets OR
  2) One or more FileInfo objects representing text files OR
  3) One or more ADComputer objects (Get-ADComputer)

**Arguments**
Specifies the arguments that will be passed to nmap
  Default: -sT -T3

**OutDir**
    Specifies the directory nmap should output XML files to
    Default: Current working directory

**CSV**
    Specifies the column in the CSV that contains the target
    Default: Not set, setting this parameter will cause #all text files# to
             be processed as CSV files

**Location**
The location of the nmap executable
  Defaults to "nmap" (assumes nmap directory is in the $PATH)

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

    "scanme.nmap.org,10.2.1.0" | .\Nmap-Scan -Location "C:\nmap\nmap.exe"
    Define the location of the nmap executable if it isn't available in PATH

    dir *.csv | .\Nmap-Scan -CSV Target
    Get an object containing text files in working directory,
    uses the column "Target" to create list of hosts
        Target, HostName
        8.8.8.8, "Google DNS"
        scanme.nmap.org,"Scan Me"
        192.168.1.1, "My Router"

    .\Nmap-Scan 192.168.1.1 -Arguments "-p 445 --script smb-vuln-ms17-010" -OutDir "2017-11-26"
    Check host 192.168.1.1 for vulnerability to EternalBlue and output XML to dated directory
    
## TO-DO
* Validate that host/subnet is valid before starting nmap
* Ability to feed in CSV with additional metadata?
