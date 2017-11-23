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
    Default: -F -T3

.Parameter Location
    The location of the nmap executable
    Defaults to "nmap" (assumes nmap directory is in the PATH)

.Example 
    dir *.txt | .\Nmap-Scan
    Get an object containing text files in working directory, read files
    and run nmap against each host specified in each file (one per line)

.Example
    .\Nmap-Scan 10.0.0.0/24 -Arguments "-T5 -A -sC -sS"
    Run nmap against a subnet with custom arguments

.Example
    .\Nmap-Scan "scanme.nmap.org,192.168.0.1"
    Run nmap against a set of hosts and/or subnets

.Notes
Written by: Ethan Sterling

Find me on:
* Twitter  : http://twitter.com/esterling_
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

#>

#requires -version 2

[CmdletBinding(SupportsShouldProcess=$True)]
param (
    [Alias ("I","IN")]
    [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
        $InputObject,
    [Alias ("ARG")]
    [Parameter()]
        $Arguments = "-F -T3", # Set sane defaults for command string
    [Alias ("NMAP")]
    [Parameter()]
        $Location = "nmap" # In case nmap is not in PATH
    )

BEGIN {
    # Get current date/time
    $ScriptStart = Get-Date

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

            $InputType = $InputObject.GetType().FullName
            switch($InputType){
                
                "System.String" {
                    # Attempt to split comma-separated strings
                    $Targets = $InputObject.Replace(" ", "").Split(",")
                    Write-Verbose "Targets from command line: $($Targets)"
                    }
                "System.IO.FileInfo" {
                    # Read hosts from file into array
                    $Targets = Get-Content($InputObject.FullName)
                    Write-Verbose "Targets from file $($InputObject.FullName): $($Targets)"
                    }
                } # END Switch

            foreach ($Target in $Targets) {

                # Confirm that target is not empty
                if($Target -ne "") {
                    
                    # Remove "/" from output file name in order to not break
                    $OutputFile = "$($Target.Replace("/", "-")).xml"

                    # Construct command line for nmap                    
                    $FullCommand = "$($Arguments) -oX $OutputFile $($Target)"
                    Write-Verbose "Running command: $($Location) $($FullCommand)"

                    # Start nmap scan
                    Write-Output "$($Target): Starting scan"
                    if ($PSCmdlet.ShouldProcess($Target,"nmap $($Arguments)")) {
                        Start-Process $Location -ArgumentList $FullCommand -Wait
                        }

                    # Once scan completes, check for existence of output file 
                    Write-Output "$($Target): Scan completed ($OutputFile)"
                    if(Test-Path $OutputFile) {Write-Verbose "Output file $($OutputFile) saved successfully"}else{Write-Verbose "Output file $($OutputFile) not found!"}
                    }
            } # END ForEach
        } # END PROCESS
    
        END {

            Write-Verbose "Processing completed"
        }

    }

}

PROCESS {Nmap-Scan}

END {

    $ScriptEnd = Get-Date
    $TimeTaken =  $ScriptEnd - $ScriptStart 
    Write-Verbose "Script completed in $($TimeTaken.Minutes) minutes and $($TimeTaken.Seconds) seconds"
}
