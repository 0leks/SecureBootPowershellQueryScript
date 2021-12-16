<#
.SYNOPSIS
    Queries the SecureBoot UEFI variables (PK, KEK, DB, DBX) and writes the
    results to a CSV file for each variable.
.DESCRIPTION
    Uses the Get-SecureBootUEFI script and some byte wrangling to parse out the
    relevant UEFI variable data for each SecureBoot variable (PK, KEK, DB, DBX)
.PARAMETER Path
    pk.txt, kek.txt, db.txt, and dbx.txt will be written to Path. Defaults to .\
.PARAMETER ForAggregation
    Appends <Device Manufacturer>\<Device Model>\<Hash of Computer Name>\ to the output Path
.PARAMETER Verbose
    Enables printing status and error messages to the console.
#>
param (
    [string]$Path = ".",
    [switch]$Verbose,
    [switch]$ForAggregation
)


## This function is adapted from https://gist.github.com/mattifestation/1a0f93714ddbabdbac4ad6bcc0f311f3
## it parses the raw data returned from the Get-SecureBootUEFI cmdlet into a well-structured object
function Get-UEFIDatabaseSigner {
<#
.SYNOPSIS
Dumps signature or hash information for whitelisted ('db' variable) or blacklisted ('dbx' variable) UEFI bootloaders.
.DESCRIPTION
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
.PARAMETER Variable
Specifies a UEFI variable, an instance of which is returned by calling the Get-SecureBootUEFI cmdlet. Only 'db' and 'dbx' are supported.
.EXAMPLE
Get-SecureBootUEFI -Name db | Get-UEFIDatabaseSigner
.EXAMPLE
Get-SecureBootUEFI -Name dbx | Get-UEFIDatabaseSigner
.EXAMPLE
Get-SecureBootUEFI -Name pk | Get-UEFIDatabaseSigner
.EXAMPLE
Get-SecureBootUEFI -Name kek | Get-UEFIDatabaseSigner
.INPUTS
Microsoft.SecureBoot.Commands.UEFIEnvironmentVariable
Accepts the output of Get-SecureBootUEFI over the pipeline.
.OUTPUTS
UEFIDBXHash
Outputs a custom object consisting of banned SHA256 hashes and the respective "owner" of each hash. "77fa9abd-0359-4d32-bd60-28f4e78f784b" refers to Microsoft as the owner.
#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateScript({ ($_.GetType().Fullname -eq 'Microsoft.SecureBoot.Commands.UEFIEnvironmentVariable') -and (($_.Name -eq 'kek') -or ($_.Name -eq 'pk') -or ($_.Name -eq 'db') -or ($_.Name -eq 'dbx')) })]
        $Variable
    )

    $SignatureTypeMapping = @{
        'C1C41626-504C-4092-ACA9-41F936934328' = 'EFI_CERT_SHA256_GUID' # Most often used for dbx
        'A5C059A1-94E4-4AA7-87B5-AB155C2BF072' = 'EFI_CERT_X509_GUID'   # Most often used for db
    }

    try {
        $MemoryStream = New-Object -TypeName IO.MemoryStream -ArgumentList @(,$Variable.Bytes)
        $BinaryReader = New-Object -TypeName IO.BinaryReader -ArgumentList $MemoryStream, ([Text.Encoding]::Unicode)
    } catch {
        throw $_
        return
    }

    # What follows will be an array of EFI_SIGNATURE_LIST structs

    while ($BinaryReader.PeekChar() -ne -1) {
        $SignatureType = $SignatureTypeMapping[([Guid][Byte[]] $BinaryReader.ReadBytes(16)).Guid]
        $SignatureListSize = $BinaryReader.ReadUInt32()
        $SignatureHeaderSize = $BinaryReader.ReadUInt32()
        $SignatureSize = $BinaryReader.ReadUInt32()

        $SignatureHeader = $BinaryReader.ReadBytes($SignatureHeaderSize)

        # 0x1C is the size of the EFI_SIGNATURE_LIST header
        $SignatureCount = ($SignatureListSize - 0x1C) / $SignatureSize

        $Signatures = 1..$SignatureCount | ForEach-Object {
            $SignatureDataBytes = $BinaryReader.ReadBytes($SignatureSize)

            $SignatureOwner = [Guid][Byte[]] $SignatureDataBytes[0..15]
            
            switch ($SignatureType) {
                'EFI_CERT_SHA256_GUID' {
                    $SignatureData = New-Object -Type PSObject -Property @{
                        'Hash' = ([Byte[]] $SignatureDataBytes[0x10..0x2F] | ForEach-Object { $_.ToString('X2') }) -join ''
                    }
                }
                'EFI_CERT_X509_GUID' {
                    $SignatureData = New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,([Byte[]] $SignatureDataBytes[16..($SignatureDataBytes.Count - 1)]))
                    $SignatureData | Add-Member -NotePropertyName "SignatureAlgorithmFriendlyName" -NotePropertyValue $SignatureData.SignatureAlgorithm.FriendlyName
                }
            }
            $SignatureData | Add-Member -NotePropertyName "SignatureType" -NotePropertyValue $SignatureType
            $SignatureData | Add-Member -NotePropertyName "SignatureOwner" -NotePropertyValue $SignatureOwner

            $SignatureData
        }
        $Signatures
    }
}

$Delimeter1 = '"'
$Delimeter2 = ","
$Delimeter = "$Delimeter1$Delimeter2$Delimeter1"
$X509MemberList = "SignatureType", "SignatureAlgorithmFriendlyName", "Thumbprint", "Subject", "Version", "Issuer", "SerialNumber", "NotBefore", "NotAfter", "SignatureOwner", "RawData"
$X509MemberListString = "$($Delimeter1)EFI_CERT_X509_GUID$Delimeter$($($X509MemberList[1..($X509MemberList.Length-1)]) -join $Delimeter)$Delimeter1"

$SHA256MemberList = "SignatureType", "Hash", "SignatureOwner"
$SHA256MemberListString = "$($Delimeter1)EFI_CERT_SHA256_GUID$Delimeter$($($SHA256MemberList[1..($SHA256MemberList.Length-1)]) -join $Delimeter)$Delimeter1"

function Signature-To-String($signature) {
    $memberlist = $X509MemberList
    switch ($signature.SignatureType) {
        'EFI_CERT_SHA256_GUID' {
            $memberlist = $SHA256MemberList
        }
        'EFI_CERT_X509_GUID' {
            $memberlist = $X509MemberList
        }
    }
    $members = $memberlist | ForEach-Object {
        $value = $signature.($_)
        #write-host "$_ = $value"
        "$Delimeter1$value$Delimeter1"
    }
    return $members
}

## Used to get hash of computer name to avoid saving identify-able info
function get-hash([string]$textToHash) {
    $hasher = new-object System.Security.Cryptography.MD5CryptoServiceProvider
    $toHash = [System.Text.Encoding]::UTF8.GetBytes($textToHash)
    $hashByteArray = $hasher.ComputeHash($toHash)
    foreach($byte in $hashByteArray)
    {
      $result += "{0:X2}" -f $byte
    }
    return $result;
}

function Process-SecureBoot-Variable([string]$variable, [string]$infoString, [string]$outputFile) {
    try {
        "$($Delimeter1)$variable$infoString" | Out-File -FilePath $outputFile
        $SHA256MemberListString | Out-File -FilePath $outputFile -Append
        $X509MemberListString | Out-File -FilePath $outputFile -Append

        $data = Get-SecureBootUEFI -Name $variable | Get-UEFIDatabaseSigner
        if($data.Count -gt 0) {
            $data | ForEach-Object {
                $result = Signature-To-String $_
                $result -join $Delimeter2 | Out-File -FilePath $outputFile -Append
            }
        }
        else {
            $result = Signature-To-String $data
            $result -join $Delimeter2 | Out-File -FilePath $outputFile -Append
        }
    }
    catch {
        if ($Verbose) {
            write-host $_
        }
    }
}

try {
    if($Verbose) {
        write-output "Running with verbose=$Verbose, path=$Path"
    }
    if($Verbose) {
        if(Confirm-SecureBootUEFI) {
            write-host "SecureBoot is enabled"
        } else {
            write-host "SecureBoot is disabled"
        }
    }

    $systemInformation = Get-CimInstance -ClassName Win32_ComputerSystem
    $computerNameHash = (get-hash($env:computername)).Substring(0,10)
    
    $dataPath = "$Path\"
    if ($ForAggregation) {
        $dataPath = "$Path\" `
                    + $systemInformation.Manufacturer + "\" `
                    + $systemInformation.Model + "\" `
                    + $computerNameHash + "\"
    }
    if($Verbose) {
        write-host "Writing data to" $dataPath
    }
    $infoString = "$Delimeter$($systemInformation.Manufacturer)$Delimeter$($systemInformation.Model)$Delimeter$computerNameHash$Delimeter1"

    New-Item -Path $dataPath -ItemType Directory -ErrorAction Silent | Out-Null

    $pkfile = $dataPath + "PK.txt"
    $kekfile = $dataPath + "KEK.txt"
    $dbfile = $dataPath + "DB.txt"
    $dbxfile = $dataPath + "DBX.txt"
    $encodedFile = $dataPath + "encoded.txt"

    Process-SecureBoot-Variable "pk" $infoString $pkfile
    Process-SecureBoot-Variable "kek" $infoString $kekfile
    Process-SecureBoot-Variable "db" $infoString $dbfile
    Process-SecureBoot-Variable "dbx" $infoString $dbxfile
}
catch {
    if($Verbose) {
        Write-Host $_
    }
    exit
}
