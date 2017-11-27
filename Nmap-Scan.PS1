<#
.Synopsis 
    Runs a series of nmap scans against a list of IP addresses or subnets 

.Description 
    Ingests a list of host names, IP addresses and/or sub nets and launches an nmap scan
    against each one in sequence. Can be fed multiple text files either through
    FileInfo objects or on the pipeline. Output is sent to an XML file in the format of
    [Host or subnet].xml in the current working dir. 

    By default will use reasonable sane nmap arguments (-F -T3) but custom arguments
    can be specified using the parameter -Arguments [args]

    If the nmap executable is not accessible from the PATH variable an alternative
    location can be specified using the parameter -Location [nmap location]

    TO-DO
    Add ability to feed in computer names from AD module
    Validate that host/subnet is valid before starting nmap
    Ability to feed in CSV with additional metadata?

.Parameter InputObject  
    Either 1) A string of host names/IP Addresses/Subnets OR
           2) One or more FileInfo objects representing text files

.Parameter Arguments
    Specifies the arguments that will be passed to nmap
    Default: -sT -T3

.Parameter OutDir
    Specifies the directory nmap should output XML files to
    Default: Current working directory

.Parameter Location
    The location of the nmap executable
    Default: nmap.exe (assumes nmap directory is in the PATH)

.Parameter CSV
    Specifies the name of the column in the CSV that contains the target
    Default: Not set, setting this parameter will cause #any text file# to
             be processed as a CSV file

.Inputs
    System.String
        You can pipe a string containing a host, or a coimma-separated
        list of hosts

    System.IO.FileInfo
        You can pipe in System.IO.FileInfo object(s) provided by cmdlets
        like Get-ChildItem

    Microsoft.ActiveDirectory.Management.ADComputer
        You can pipe in object(s) returned from the Get-ADComputer Active
        Directory cmdlet

.Outputs
    System.Object[]
        This script returns a PSObject with the following properties:
            Target - The target of the nmap scan
            Arguments - The command line args passed to nmap
            StartTime - The start time of the scan
            FinishTime - The end time of the scan
            Duration - The duration of the scan
            OutFile - The location of the XML file output by nmap
            Hash - The SHA254 hash of the OutFile


.Example 
    dir *.txt | .\Nmap-Scan
    Get an object containing text files in working directory, read files
    and run nmap against each host specified in each file (one per line)

.Example
    dir *.csv | .\Nmap-Scan -CSV Target
    Get an object containing text files in working directory,
    uses the column "Target" to create list of hosts
        Target, HostName
        8.8.8.8, "Google DNS"
        scanme.nmap.org,"Scan Me"
        192.168.1.1, "My Router"

.Example
    .\Nmap-Scan 10.0.0.0/24 -Arguments "-T5 -A -sC -sS"
    Run nmap against a subnet with custom arguments

.Example
    .\Nmap-Scan 192.168.1.1 -Arguments "-p 445 --script smb-vuln-ms17-010" -OutDir "2017-11-26"
    Check host 192.168.1.1 for vulnerability to EternalBlue and output XML to dated directory

.Example
    .\Nmap-Scan "scanme.nmap.org,192.168.0.1"
    Run nmap against a set of hosts and/or subnets

.Example
    Get-ADComputer -Filter {Name -like "HostName"} | .\Nmap-Scan.PS1
    Run nmap against objects returned by Get-ADComputer

.Example
    "scanme.nmap.org,10.2.1.0" | .\Nmap-Scan -Location "C:\nmap\nmap.exe"
    Define the location of the nmap executable if it isn't available in PATH

.Notes
Written by: Ethan Sterling

Find me on:
* Twitter  : https://twitter.com/esterling_
* Medium   : https://medium.com/@esterling_

License:

The MIT License (MIT)

Copyright (c) 2017 Ethan Sterling

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Change Log:
V0.1 - 23/11/2017 - Initial version
V0.2 - 25/11/2017 - Added handler for ADComputer objects
v0.3 - 26/11/2017 - Change handling of input to make it more robust, support passing of 
                      arrays of different data types into script
                    Add ability to output XML files to specific directory using parameter
                      -OutDir (ex. -OutDir "C:\NmapResults\2017-11-26")

#>

#requires -version 2

[CmdletBinding(SupportsShouldProcess=$True)]
param (
    [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
        $InputObject,
    [Parameter()]
        [string]$Arguments = "-sT -T3", # Set sane defaults for command string
    [Parameter()]
        [string]$Location = "nmap", # In case nmap is not in PATH
    [Parameter()]
        [string]$OutDir = $pwd, # Specify the directory nmap should output XML files to
    [Parameter()]
        [string]$CSV # Specify the directory nmap should output XML files to
    )

BEGIN {
    # Get current date/time
    $ScriptStart = Get-Date

    # Check if selected output folder exists, create if required
    if(-not(Resolve-Path $OutDir -ErrorAction SilentlyContinue -ErrorVariable _rperror)){
        Write-Verbose "OutDir $($outdir) not found, creating..."
        mkdir $_rperror[0].TargetObject | out-null
    }
    $OutDir = Resolve-Path $OutDir
    Write-Verbose "Set output directory to $($OutDir)"

    # Define function to correctly handle input object depending on object type
    function Process-Input($In) {

        # Get ObjectType of input
        $InputType = $In.GetType().FullName
        Write-Verbose "Object Type: $($InputType)"

        $out = @()

        switch($InputType){
                
            "System.String" {
                # Attempt to split comma-separated strIngs
                $Out = $In.Replace(" ", "").Split(",")
                Write-Verbose "Target(s) from command lIne: $($Out)"
                }
            "System.IO.FileInfo" {
                # Read hosts from file Into array
                if($CSV.Length -gt 0){
                    Import-CSV $in.FullName |%{
                        $out += $_.($CSV)
                    }
                }
                else {
                    $Out = Get-Content($In.FullName)
                    Write-Verbose "Target(s) from file $($In.FullName): $($Out)"
                    }
                }
            "Microsoft.ActiveDirectory.Management.ADComputer" {
                # Accept objects from AD modules
                $In |%{$Out += $_.DNSHostName}
                Write-Verbose "Target(s) from ADComputer object: $($Out)"
                }
            } # END Switch

        Return $Out

    } # END Fucntion Process-Input

    # Define main function
    function Nmap-Scan {
    
        BEGIN {

            # Check if input is some variation of "Help"
            if ($InputObject -match '/\?|/help|--h|--help') { 
                $MyInvocation = (Get-Variable -Name MyInvocation -Scope Script).Value
                get-help -full ($MyInvocation.MyCommand.Path)   
		        exit 
	        } #END If
        } #END BEGIN
    
        PROCESS {
            
            # Initialise target array
            $Targets = @()

            # Check if input is a generic array or single object and pass to ProcessInput function
            if($InputObject.GetType().FullName -eq "System.Object[]") {
                $InputObject |% {$Targets += Process-Input $_}
                }
            else {
                $Targets = Process-Input $InputObject
            }

            foreach ($Target in $Targets) {

                # Confirm that target is not empty
                if($Target -ne "") {
                    
                    # Initialise Output Object
                    $OutputObject = New-Object psobject -Property @{
                        Target = $Target;
                        Arguments = $Arguments;
                        StartTime = Get-Date;
                        FinishTime = $NULL;
                        Duration = $NULL;
                        OutFile = $NULL;
                        Hash = $NULL
                    }

                    # Remove "/" from output file name in order to not break
                    $OutputFile = "$($OutDir)\$($Target.Replace("/", "-")).xml"
                    $OutputObject.OutFile = $OutputFile

                    # Construct command line for nmap                    
                    $FullCommand = "$($Arguments) -oX $OutputFile $($Target)"

                    # Start nmap scan
                    Write-Verbose "Scan started at $($OutputObject.StartTime)"
                    if ($PSCmdlet.ShouldProcess($Target,"$($Location) $($Arguments)")) {
                        Start-Process $Location -ArgumentList $FullCommand -Wait
                        }
                    $OutputObject.FinishTime = Get-Date
                    Write-Verbose "Scan completed at $($OutputObject.FinishTime)"
                    $OutputObject.Duration = $OutputObject.FinishTime - $OutputObject.StartTime

                    # Once scan completes, check for existence of output file 
                    if(Test-Path $OutputFile) {
                        Write-Verbose "Output file $($OutputFile) saved successfully"
                        $OutputObject.Hash = (Get-FileHash -Algorithm SHA256 $OutputFile).Hash
                        }
                    else {
                        Write-Verbose "Output file $($OutputFile) not found!"
                        }
                    # Send $OutputObject to pipeline
                    $OutputObject
                    }
            } # END ForEach
        } # END PROCESS
    
        END {

            Write-Verbose "Processing completed"
        }

    } # END Function Nmap-Scan

}

PROCESS {Nmap-Scan}

END {

    $ScriptEnd = Get-Date
    $TimeTaken =  $ScriptEnd - $ScriptStart 
    Write-Verbose "Script completed in $($TimeTaken.Minutes) minutes and $($TimeTaken.Seconds) seconds"
} 
