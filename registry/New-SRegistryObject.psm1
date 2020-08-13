<#
.SYNOPSIS
Retrieves specified registry keys and outputs in CSV or human format.

.DESCRIPTION
New-SRegistryObject creates a custom object that mimics a registry key and value.
Some registry keys do not have any values and therefor those object properties
will be empty. The output will produce an object that can be converted to JSON or CSV.
Null or empty values are accepted due to registry keys not containing values.

.PARAMETER Name
The full path to the registry key

.PARAMETER KeyCount
An integer for the number of subkeys a registry key has

.PARAMETER ValueCount
An integer for the number of values in the key

.PARAMETER ValueName
The name of the value

.PARAMETER ValueType
The Values regsitry type (String, Binary, Qword etc)

.PARAMETER Value
The data within the named value

.INPUTS
All parameters can be given via pipeline.

.OUTPUTS
Returns a custom PSObject with registry info for each specific key or value
#>
Function New-SRegistryObject
{
    Param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)][AllowEmptyString()][String]$Name,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)][AllowEmptyString()][Int]$KeyCount,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)][AllowEmptyString()][Int]$ValueCount,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)][AllowEmptyString()][String]$ValueName,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)][AllowEmptyString()][String]$ValueType,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)][AllowEmptyString()][String]$Value
    )

    # Create the custom object and define the properties of the object
    $registryObject = New-Object -TypeName PSObject
    Add-Member -InputObject $registryObject -MemberType NoteProperty -Name 'KeyName' -Value $Name
    Add-Member -InputObject $registryObject -MemberType NoteProperty -Name 'SubKeyCount' -Value $KeyCount
    Add-Member -InputObject $registryObject -MemberType NoteProperty -Name 'ValueCount' -Value $ValueCount
    Add-Member -InputObject $registryObject -MemberType NoteProperty -Name 'ValueName' -Value $ValueName
    Add-Member -InputObject $registryObject -MemberType NoteProperty -Name 'ValueType' -Value $ValueType
    Add-Member -InputObject $registryObject -MemberType NoteProperty -Name 'Value' -Value $Value

    # Returning object
    $registryObject
}