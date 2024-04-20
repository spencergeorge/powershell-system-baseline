<#
.SYNOPSIS
String modifier. Prepends all HKU\ root keys (one for each user and defaults) to the
given input so that all HKEY_USER keys can be searched.

.DESCRIPTION
Get-SRegistryHKU is used as a helper function to the Get-SRegistryItem function.
To prevent users from hardcoded SID's of the HKEY_USERS HIVE, this function
will enumerate all base keys of HKEY_USERS given a specific subkey inside HKU.

Basically this function uses regex to modify the key names to include each
SID under HKEY_USERS and then sends the string back to Get-SRegistryItem for processing

Users don't have direct access to this function but only
have to specify in their source list to Get-SRegistryItem 
with the notation of "HKU:\SomePath"

.PARAMETER SubPath
The subpath to search in each of the HKU subkeys.

.EXAMPLE
"Software\Microsoft\Internet Explorer\TypedUrls
Not: "HKU:\Software\Microsoft\Internet Explorer\TypedUrls

.OUTPUTS
Returns the resulting object from Get-SRegistryItem
#>
Function Get-SRegistryHKU
{
    Param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)][String]$SubPath
    )

    # Create array to store registry objects after calling Get-SRegistryItem
    [array]$regItems = @()

    # Get the HKEY_USERS HIVE. hkuRoot is type Registry
    $hkuRoot = Get-Item "HKU:\"

    # Loop through all the SID root keys for the specific subkey
    # Store each iteration into the array
    $hkuRoot.GetSubKeyNames() | ForEach-Object -Process {
        $temp = ('HKU:\' + $_) + '\' + $SubPath
        #Write-Host "Processing: $temp"
        $regItems += Get-SRegistryItem -Path $temp
    }

    # Return HKU objects
    $regItems
}