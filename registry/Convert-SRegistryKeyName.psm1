<#
.SYNOPSIS
Converts registry paths to correct syntax needed for registry calls.

.DESCRIPTION
Given a string, Convert-SRegistryKeyName will check if the string starts with the proper root
registry key so that it can be correctly called by Get-childitem and Get-item for 
registry paths.

.PARAMETER KeyName
A string, defining the path to look in the registry.

.EXAMPLE
HKU:\Some\Sub\Key will send the subkey(part after HKU:\) through each user key in HKEY_USERS

.EXAMPLE
HKEY_CLASSES_ROOT:\.docx will transform to HKCR:\.docx

.EXAMPLE
HKEY_CURRENT_USER:\AppEvents will transform to HKCU:\AppEvents

.EXAMPLE
HKEY_LOCAL_MACHINE:\HARDWARE will transform to HKLM:\HARDWARE

.EXAMPLE
HKEY_USERS:\S-1-5-18\Console will transform to HKU:\S-1-5-18\Console

.EXAMPLE
HKEY_CURRENT_CONFIG:\Software\Fonts will transform to HKCC:\Software\Fonts

.INPUTS
A string. Convert-SRegistryKeyName does not accept piped input.

.OUTPUTS
A string transformed if the condition is matched.
#>
Function Convert-SRegistryKeyName
{
    Param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)][String]$KeyName
    )

    switch -Regex ($KeyName)
    {
        'HKU:?\\'
        {
            if($KeyName -notmatch 'HKU:\\s-' -and $KeyName -notmatch 'HKU:\\\.DEFAULT')
            {
                $i = $KeyName.IndexOf('\') + 1
                $KeyName = $KeyName.Substring($i,$KeyName.Length - $i)

                Get-SRegistryHKU -SubPath $KeyName
        
                break
            }
        }
        'HKEY_CLASSES_ROOT' {$KeyName = $KeyName -replace 'HKEY_CLASSES_ROOT','HKCR:'}
        'HKEY_CURRENT_USER' {$KeyName = $KeyName -replace 'HKEY_CURRENT_USER','HKCU:'}
        'HKEY_LOCAL_MACHINE' {$KeyName = $KeyName -replace 'HKEY_LOCAL_MACHINE','HKLM:'}
        'HKEY_USERS' {$KeyName = $KeyName -replace 'HKEY_USERS','HKU:'}
        'HKEY_CURRENT_CONFIG' {$KeyName = $KeyName -replace 'HKEY_CURRENT_USER','HKCC:'}
        '^(\w{3,4})\\' {$KeyName = $KeyName -replace "^(\w{3,4})","$&:"}
    }
    $KeyName = $KeyName -replace '\[',''
    $KeyName = $KeyName -replace '\]',''
    $KeyName
}
