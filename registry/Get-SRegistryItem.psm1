<#
.SYNOPSIS
Retrieves registry keys and values and outputs in a simplified format from get-childitem.
Pairs with Compare-RegistryItem

.DESCRIPTION
Get-SRegistryItems is a recursive function that enumerates the registry given a basekey.
It first checks if the given key has values. If so it will iterate
through each value and create an object. Then it checks for subkeys. If subkeys exist
it will call itself with that subkey starting the fucntion all over.

.PARAMETER Path
The basekey to start enumerating in the registry.

.PARAMETER Switch
A switch toggling recursive lookups (DEFAULT false)

.OUTPUTS
An array of custom registry objects
#>
Function Get-SRegistryItem
{
    Param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)][String]$Path,
        [Parameter(Mandatory=$false,ValueFromPipeline=$true)][Switch]$Recurse
    )

    #If(Get-PSDrive -PSProvider Registry -Name HKU)
    # Create new PSDrive to enumerate HKEY_USERS hive.
    New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
    # Create new PSDrive to enumerate HKEY_USERS hive.
    New-PSDrive -PSProvider Registry -Name HKCR -Root HKEY_CLASSES_ROOT -ErrorAction SilentlyContinue | Out-Null
    # Create new PSDrive to enumerate HKEY_USERS hive.
    New-PSDrive -PSProvider Registry -Name HKCC -Root HKEY_CURRENT_CONFIG -ErrorAction SilentlyContinue | Out-Null

    $Path = Convert-SRegistryKeyName -KeyName $Path
    
    [array]$items = @()

    # Test if registry key exists. If not skip
    if(Test-Path $Path)
    {
        # Get the registry item (key only, no values), catch any errors and continue
        try
        {
         #   Write-host "Processing: $Path"
            $Key = Get-Item $Path -ErrorAction SilentlyContinue
        }
        catch [System.Security.SecurityException]
        {
            Write-host "Permission Denied: $Path"
        }
        
        # Create registry item (key only, no values)
        $items += New-SRegistryObject `
            -Name $Key.Name `
            -KeyCount $Key.SubKeyCount `
            -ValueCount $Key.ValueCount `
            -ValueName $null `
            -ValueType $null `
            -Value $null         
           
        # Check if registry item has values
        # If so create objects for each value
        if($Key.ValueCount -gt 0)
        {
            # Get name of values in key and iterate
            $Key.GetValueNames() | ForEach-Object {
                $regValueKind = $Key.GetValueKind("$_")
                $regValueName = $_
                
                # Some registry types cannot be directly written to file
                # These listed below must be converted from an array to a string
                switch ($regValueKind)
                {
                    'Binary' {$regValue = $Key.GetValue("$regValueName") -join ' '}
                    'MultiString' {$regValue = $Key.GetValue("$regValueName") -join ' '}
                    'None' {$regValue = $Key.GetValue("$regValueName") -join ' '} 
                    default {$regValue = $Key.GetValue("$regValueName")}
                }

                # Attempt to make custom objects with value.
                # The catch statement is to catch values that cannot
                # Be converted to CSV format such as those in the switch 
                # statement above
                try
                {
                    $items += New-SRegistryObject `
                        -Name $Key.Name `
                        -KeyCount $null `
                        -ValueCount $null `
                        -ValueName $_ `
                        -ValueType $Key.GetValueKind("$_") `
                        -Value $regValue
                }
                catch
                {
                    $_.Exception.ToString()
                    write-host $Key.Name
                    write-host $regValueName
                    write-host $regValueKind
                }
            }
        }
        
        if($PSBoundParameters.ContainsKey('Recurse'))
        {
            # If this key has subkeys recurse
            if($key.SubKeyCount -gt 0)
            {
                # Get the subkey names and iterate
                $key.GetSubKeyNames() | ForEach-Object {
                    $subKeyName = $_

                    # Combine key and subkeyname to make full key path for new search
                    switch -Regex ($key.Name)
                    {
                        'HKEY_' {$subKey = (Convert-SRegistryKeyName $_) + "\$subKeyName"}                    
                        default {$subKey = $key.Name}
                    }

                    # Recursive function lookup
                    Get-SRegistryItem -Path $subKey -Recurse
                }
            }
        }
    }

    # Cleanup PSDrives that were created.
    Remove-PSDrive -Name HKU
    Remove-PSDrive -Name HKCR
    Remove-PSDrive -Name HKCC

    # Return items.
    $items #| ForEach-Object -Process {$_}
    Remove-Variable items
}