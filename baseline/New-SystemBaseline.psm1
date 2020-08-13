Function Write-ProgressHelper 
{
    param (
        [Parameter(Mandatory=$true)][int]$StepNumber,
        [Parameter(Mandatory=$true)][string]$Message,
        [Parameter(Mandatory=$true)][string]$Title
    )

    Write-Progress -Activity $Title -Status $Message -PercentComplete (($StepNumber / $steps) * 100) -Id 1
}

<#
.SYNOPSIS
Performs system baseline.

.DESCRIPTION
The New-SystemBaseline.ps1 script gathers important system information from key areas
to create a baseline used for forensic analysis. If no individual components are selected
the script will create a baseline for all components.

.PARAMETER Destination
Specifies the name and path for the output file. By default,
New-SystemBaseline.ps1 generates a name from the date and time it runs, and
saves the output in the local directory.

.PARAMETER Users
Specifies collection of local users.

.PARAMETER Groups
Specifies collection of local groups.

.PARAMETER GroupMembership
Specifies collection of local group memberships.

.PARAMETER LoggedOnUsers
Specifies collection of currently logged on users.

.PARAMETER Processes
Specifies collection of running processes.

.PARAMETER Services
Specifies collection of services and their states.

.PARAMETER NetworkInfo
Specifies collection of network settings.

.PARAMETER SocketsListening
Specifies collection of sockets in the listening state.

.PARAMETER SystemInfo
Specifies collection of system information.

.PARAMETER MappedDrives
Specifies collection of mapped drives.

.PARAMETER PlugNPlay
Specifies collection of plug and play devices.

.PARAMETER Shares
Specifies collection of folder, file and printer shares.

.PARAMETER Tasks
Specifies collection of scheduled tasks.

.PARAMETER HumanReadable
Specifies that the output of the script return a human readable format. Defaults to CSV if this is not set.

.PARAMETER Registry
Specifies collection forensically relevant registry keys

.INPUTS
None. You cannot pipe objects to New-SystemBaseline.ps1.

.OUTPUTS
Console or File. New-SystemBaseline does not return an object.
It will print to the console or write the contents to a file.

.EXAMPLE
PS> .\New-SystemBaseline.ps1

.EXAMPLE
PS> .\New-SystemBaseline.ps1 -HumanReadable -Destination C:\Data\Baseline_20190822.txt

.EXAMPLE
PS> .\New-SystemBaseline.ps1 -Destination C:\Data\Baseline_20190822.txt -Processes -SocketsListening

.EXAMPLE
PS> .\New-SystemBaseline.ps1 -Processes -SocketsListening

#>
Function New-SystemBaseline
{
    # Defining parameters for the script.
    Param (
            [Parameter(Mandatory=$false,ValueFromPipeline=$true)][String]$Destination,
            [Parameter(Mandatory=$false,ValueFromPipeline=$true)][Switch]$HumanReadable,
            [Parameter(Mandatory=$false,ValueFromPipeline=$true)][Switch]$Users,
            [Parameter(Mandatory=$false,ValueFromPipeline=$true)][Switch]$Groups,
            [Parameter(Mandatory=$false,ValueFromPipeline=$true)][Switch]$GroupMembership,
            [Parameter(Mandatory=$false,ValueFromPipeline=$true)][Switch]$LoggedOnUsers,
            [Parameter(Mandatory=$false,ValueFromPipeline=$true)][Switch]$Processes,
            [Parameter(Mandatory=$false,ValueFromPipeline=$true)][Switch]$Services,
            [Parameter(Mandatory=$false,ValueFromPipeline=$true)][Switch]$NetworkInfo,
            [Parameter(Mandatory=$false,ValueFromPipeline=$true)][Switch]$SocketsListening,
            [Parameter(Mandatory=$false,ValueFromPipeline=$true)][Switch]$SystemInfo,
            [Parameter(Mandatory=$false,ValueFromPipeline=$true)][Switch]$MappedDrives,
            [Parameter(Mandatory=$false,ValueFromPipeline=$true)][Switch]$PlugNPlay,
            [Parameter(Mandatory=$false,ValueFromPipeline=$true)][Switch]$Shares,
            [Parameter(Mandatory=$false,ValueFromPipeline=$true)][Switch]$Tasks,
            [Parameter(Mandatory=$false,ValueFromPipeline=$true)][Switch]$Registry
    )

    # This if condiditon is triggered when the execution of the scripts requires gathering all component baseline information.
    # When any switch for individual components is set, this condition will return false and will not execute.
    # Otherwise if only HumanReadable, or Destination or both are set, this will turn on all parameter switches.
    if(($PSBoundParameters.ContainsKey('Destination') -and $PSBoundParameters.ContainsKey('HumanReadable') -and $PSBoundParameters.Count -eq 2) `
        -or ($PSBoundParameters.ContainsKey('Destination') -and $PSBoundParameters.Count -eq 1) `
        -or ($PSBoundParameters.ContainsKey('HumanReadable') -and $PSBoundParameters.Comparer -eq 1) `
        -or $PSBoundParameters.Count -eq 0)
    {
        $PSBoundParameters.Add('Users',$null)
        $PSBoundParameters.Add('Groups',$null)
        $PSBoundParameters.Add('GroupMembership',$null)
        $PSBoundParameters.Add('LoggedOnUsers',$null)
        $PSBoundParameters.Add('Processes',$null)
        $PSBoundParameters.Add('Services',$null)
        $PSBoundParameters.Add('NetworkInfo',$null)
        $PSBoundParameters.Add('SocketsListening',$null)
        $PSBoundParameters.Add('SystemInfo',$null)
        $PSBoundParameters.Add('MappedDrives',$null)
        $PSBoundParameters.Add('PlugNPlay',$null)
        $PSBoundParameters.Add('Shares',$null)
        $PSBoundParameters.Add('Tasks',$null)
    }

    $script:steps = ([System.Management.Automation.PsParser]::Tokenize((Get-Content "$PSCommandPath"), [ref]$null) | Where-Object { $_.Type -eq 'Command' -and $_.Content -eq 'Write-ProgressHelper' }).Count
    
    $stepCounter = 0
    
    # Initializing array for all produced objects from each component.
    [hashtable]$outputObjects = @{}
    
    # Sets system setting to enumerate all objects in a collection regardless of screen size
    # This will expand all columns to show all their text.
    $FormatEnumerationLimit=-1

    # Gather date and hostname. This is included in every report.    
    $outputObjects['Date'] = Get-Date
    $outputObjects['Hostname'] = $env:COMPUTERNAME

    # This switch statment checks the script parameters that were turned on.
    # For each one of the parameters that is selected to run, their code is processed
    # and added to the outputObjects hashtable. 
    switch($PSBoundParameters.Keys)
    {
        # Gather local user information
        'Users'
        {
            Write-ProgressHelper -Title 'Gathering' -Message 'Local User Information' -StepNumber ($stepCounter++)
            $outputObjects['Users'] = Get-LocalUser 
        }
        # Gather local group information
        'Groups' 
        {
            Write-ProgressHelper -Title 'Gathering' -Message 'Local Group Information' -StepNumber ($stepCounter++)
            $outputObjects['Groups'] = Get-LocalGroup
        }
        # Gather local group memberships
        'GroupMembership' 
        {
            $localGroups = Get-LocalGroup
            $localGroupArray = @()
        
            # I know this is a nested loop. With time I will refactor
            # Iterates through each local group then each member.
            # Adds each member of a group to a new line of the output.
            ForEach($group in $localGroups)
            {
                Write-ProgressHelper -Title 'Gathering' -Message "Local Group Memberships for $group" -StepNumber ($stepCounter++)
                # Gather members of this specific group
                $members = Get-LocalGroupMember -Group $group
            
                # For each member of the group create custom object with
                # group name and username then add to output.
                ForEach($member in $members)
                {
                    Write-ProgressHelper -Title 'Gathering' -Message "Local Group Memberships for user: $member" -StepNumber ($stepCounter++)
                    $myObj = New-Object -TypeName PSObject
                    Add-Member -InputObject $myObj -MemberType NoteProperty -Name 'Group' -Value $group.Name
                    Add-Member -InputObject $myObj -MemberType NoteProperty -Name 'User' -Value $member
                    $localGroupArray += $myObj
                }
            }
        
            # Add all group membership objects to hashtable for output
            $outputObjects['Group Membership'] = $localGroupArray
        }
        # Gather logged on users.
        # This will gather all logged on users and interactively seperately.
        'LoggedOnUsers' 
        {
            Write-ProgressHelper -Title 'Gathering' -Message 'Interactive logged on users' -StepNumber ($stepCounter++)

            # Interactive Sessions
            $outputObjects['Interactive Logons'] = Get-Process -Name "Explorer" -IncludeUserName | `
                Select-Object -Unique -Property UserName
            
            Write-ProgressHelper -Title 'Gathering' -Message 'All logged on users' -StepNumber ($stepCounter++)

            # All sessions
            $outputObjects['Logons'] = (Get-WmiObject Win32_LoggedOnUser | `
                Select-Object Antecedent -Unique).antecedent | `
                ForEach-Object -Process {
                    $_.substring($_.indexof('Name'),($_.length) - $_.indexof('Name')) } | `
                        ForEach-Object -Process { $_.replace('Name=','')}
        }
        # Gather running processes.
        'Processes' 
        {
            $processList = Get-Process -IncludeUserName
            $procArray = @()
        
            # The formatting of the Get-process command would not produce consistent results
            # with whitespace. This was breaking the comparision script.
            # Therefor I had to create a custom object for each process.
            ForEach($process in $processList)
            {
                Write-ProgressHelper -Title 'Gathering' -Message "Running Processes: $process" -StepNumber ($stepCounter++)

                $procObj = New-Object -TypeName PSObject
                Add-Member -InputObject $procObj -MemberType NoteProperty -Name 'PID' -Value $process.ID
                Add-Member -InputObject $procObj -MemberType NoteProperty -Name 'SI' -Value $process.SI
                Add-Member -InputObject $procObj -MemberType NoteProperty -Name 'Name' -Value $process.ProcessName
                $procArray += $procObj
            }

            # Add all process objects to the hash.
            $outputObjects['Processes'] += $procArray
        }
        # Gather all services and their states.
        'Services' 
        {
            Write-ProgressHelper -Title 'Gathering' -Message 'All Services and Their States' -StepNumber ($stepCounter++)
            $outputObjects['Service'] = Get-Service
        }
        # Gather network settings.
        'NetworkInfo' 
        {
            # Neither Get-NetTCPSettings nor Get-NetAdapter nor Get-NetIPAddress
            # gathered everything in a single command. Therefor I create a custom
            # object to store the properties I want from each command matching
            # on ifIndex.
            [array]$netArray = @()
            ForEach($ip in (Get-NetIPAddress))
            {
                Write-ProgressHelper -Title 'Gathering' -Message "Network settings: $ip" -StepNumber ($stepCounter++)
                $netObj = New-Object -TypeName PSObject
                $netAdapters = Get-NetAdapter | Where-Object -Property ifIndex -eq $ip.ifIndex 
                Add-Member -InputObject $netObj -MemberType NoteProperty -Name 'ifIndex' -Value $ip.ifIndex
                Add-Member -InputObject $netObj -MemberType NoteProperty -Name 'Name' -Value $netAdapters.Name
                Add-Member -InputObject $netObj -MemberType NoteProperty -Name 'IPAddress' -Value $ip.IPAddress
                Add-Member -InputObject $netObj -MemberType NoteProperty -Name 'MacAddress' -Value $netAdapters.MacAddress
                Add-Member -InputObject $netObj -MemberType NoteProperty -Name 'Status' -Value $netAdapters.Status
                Add-Member -InputObject $netObj -MemberType NoteProperty -Name 'LinkSpeed' -Value $netAdapters.LinkSpeed

                $netArray += $netObj
            }
        
            $outputObjects['Network Info'] = $netArray
        }
        # Gather sockets in the listening state.
        'SocketsListening' 
        {
            Write-ProgressHelper -Title 'Gathering' -Message 'Sockets in the Listening State' -StepNumber ($stepCounter++)

            $outputObjects['Sockets'] = Get-NetTCPConnection -State Listen
        }
        # Gather system info.
        'SystemInfo' 
        {
            Write-ProgressHelper -Title -Message 'System Information' -StepNumber ($stepCounter++)

            # The Get-ComputerInfo CMDLET returns a lot of informatnoi in the opposite format that is needed.
            # I only select two properties the name and its value for each object.
            $outputObjects['System Info'] = (Get-ComputerInfo).PSobject.Properties | Select-Object -Property @{E={$_.Name};L="System Info Property"}, Value
        }
        # Get system drives (this includes mapped drives)
        'MappedDrives' 
        {
            Write-ProgressHelper -Title 'Gathering' -Message 'System Drives (this includes mapped drives)' -StepNumber ($stepCounter++)

            $outputObjects['Mapped Drives'] = Get-PsDrive
        }
        # Get plug and play devices
        'PlugNPlay' 
        {
            Write-ProgressHelper -Title 'Gathering' -Message 'Plug and Play Devices' -StepNumber ($stepCounter++)

            $outputObjects['PlugNPlay Devices'] = Get-PnpDevice
        }
        # Get Shared Resources. This includes folders, files and printers
        'Shares' 
        {
            Write-ProgressHelper -Title 'Gathering' -Message 'Shared Resources' -StepNumber ($stepCounter++)

            $outputObjects['Shared Files and Directories'] = Get-SmbShare
            $outputObjects['Shared Printers'] = Get-Printer | Where-Object -Property Shared -eq $true
        }
        # Get all scheduled tasks.
        'Tasks' 
        {
            Write-ProgressHelper -Title 'Gathering' -Message 'Scheduled Tasks' -StepNumber ($stepCounter++)

            $outputObjects['Tasks'] = Get-ScheduledTask
        }
        # Get forensically relevant registry keys
        'Registry'
        {
            $registryArray=@(
                "HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
                "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                "HKU\Software\Microsoft\Windows\CurrentVersion\Run",
                "HKU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\Tasks",
                "HKLM\SYSTEM\CurrentControlSet\SERVICES\",
                "HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR",
                "HKU\Software\Microsoft\Internet Explorer\TypedUrls",
                "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\")
            $registryOutputArray=@()
            $registryArray | ForEach-Object -Process { 
                    Write-ProgressHelper -Title 'Gathering' -Message "Forensically relevant registry key: $_" -StepNumber ($stepCounter++)
                    $registryOutputArray += Get-SRegistryItem -Path $_ -Recurse
                }
            $outputObjects['Registry'] += $registryOutputArray
        }
    }

    # This for loop iterates through each of the component keys in the
    # output hashtable. It will output each key and its corresponding values
    # in either CSV or human readable format depending on if HumanReadable is set.
    # If destination is set it will write out to that file otherwise to the console.
    # If destination is not set, it will automatically write in human readable format.
    #
    # i is used to only denote the first iteration of the for loop. If destination is set
    # it will only attempt to create the destination file the first time through the loop.
    $i=1
    ForEach($key in $outputObjects.Keys)
    {
        Write-ProgressHelper -Title 'Writing Output' -Message "$key" -StepNumber ($stepCounter++)

        # Check if the Destination string was set on script call.
        if($PSBoundParameters.ContainsKey('Destination'))
        {
        
            if((Test-Path $Destination) -and $i -eq 1)
            {
                Remove-Item $Destination
            }
            
            # This writes the progress bar to the console when exporting information to a file.
            # It divides the current iteration through keys by the total number of keys in the hash.
            Write-Progress -Activity "Writing items to $Destination" `
                -Status (($i/$outputObjects.Count * 100).ToString("#") + "% Complete") `
                -PercentComplete ($i/$outputObjects.Count * 100) `
                -Id 2 `
                -ParentId 1
        
            # Checks if HumanReadable was set on script call.
            # If so creates the human readable form with format table command.
            # It creates a header statement with key being the hashtable key.
            # Else it converts each value to CSV and outputs to file.
            if($PSBoundParameters.ContainsKey('HumanReadable'))
            {
                "Start============== $key ===================" | Out-File $Destination -Append
                
                if($key -eq 'Registry')
                {
                    "The registry will print in the following format" | Out-File $Destination -Append
                    "KeyName`tSubKeyCount`tValueCount" | Out-File $Destination -Append
                    "`tValueName`tValueType`tValue`r`n" | Out-File $Destination -Append
                    
                    $tmpKeyName=""
                    
                    $outputObjects[$key] | ForEach-Object -Process {
                        
                        if($tmpKeyName -ne "$($_.KeyName)`t$($_.SubKeyCount)`t$($_.ValueCount)" -and $_.ValueCount -ne 0)
                        {
                            $tmpKeyName = "`r`n$($_.KeyName)`t$($_.SubKeyCount)`t$($_.ValueCount)" 
                            $tmpKeyName | Out-File $Destination -Append
                        }
                    
                        "`t$($_.ValueName)`t$($_.ValueType)`t$($_.Value)" | Out-File $Destination -Append
                    }
                }
                else
                {
                    $outputObjects[$key] | Format-Table -Property * | Out-String -Width 1028 | Out-File $Destination -Append
                }
                                
                "End================ $key ===================" | Out-File $Destination -Append
                "`r`n" | Out-File $Destination -Append
            }
            else
            {
                $outputObjects[$key] | ConvertTo-Json | Out-File $Destination -Append
                #$outputObjects[$key] | ConvertTo-Csv | Out-File $Destination -Append
            }
        }
        # Outputs to console in human readable format if Destination is not set.
        else
        {
            $outputObjects[$key] | Format-Table -AutoSize -Property * | Out-String -Width 4096 | Out-Host
        }
        
        $i++
    }
} 

Export-ModuleMember -Function New-SystemBaseline