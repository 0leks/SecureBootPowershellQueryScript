
# Overview

This is a utility PowerShell script for investigating SecureBoot UEFI variables.

## Description

It queries the SecureBoot UEFI variables (PK, KEK, DB, DBX) and writes the results to a CSV file for each variable.  
Uses the `Get-SecureBootUEFI` script and some byte wrangling to parse out the relevant information.

## Output Format

For each output file (pk.txt, kek.txt, db.txt, dbx.txt),  
Line 1: `"<Variable Name>","<Manufacturer>","<Model>","<5 bytes of SHA1 hash of Computer Name>"`  
Line 2: List of the comma separated values for `EFI_CERT_SHA256_GUID` entries  
Line 3: List of the comma separated values for `EFI_CERT_X509_GUID` entries  
Line 4+: Each entry of the UEFI variable gets its own line.  
&emsp;&emsp;&emsp;&emsp;(Each line starts with `EFI_CERT_SHA256_GUID` or `EFI_CERT_X509_GUID` to distinguish the schema)  

## Optional Parameters

`-Path <String>` pk.txt, kek.txt, db.txt, and dbx.txt will be written to Path. Defaults to .\

`-ForAggregation` Appends `<Device Manufacturer>\<Device Model>\<5 bytes of SHA1 hash of Computer Name>` to the output Path

`-Verbose` Enables printing status and error messages to the console.

## Usage Examples

`.\Collect-SecureBootUEFI-Info.ps1`  
`.\Collect-SecureBootUEFI-Info.ps1 -Verbose -ForAggregation -Path ./my_sb_uefi_data`

## Output Examples

### DB

```
"db","LENOVO","30D0S7RX02","FEDCBA9876"
"EFI_CERT_SHA256_GUID","Hash","SignatureOwner"
"EFI_CERT_X509_GUID","SignatureAlgorithmFriendlyName","Thumbprint","Subject","Version","Issuer","SerialNumber","NotBefore","NotAfter","SignatureOwner","RawData"
"EFI_CERT_X509_GUID","sha256RSA","CB0259714826C867D1422C310B88150160398F0B","CN=Lenovo UEFI CA 2014, O=Lenovo, S=North Carolina, C=US","3","CN=Lenovo UEFI CA 2014, O=Lenovo, S=North Carolina, C=US","03094862903475928734958723094D","01/24/2014 08:14:24","01/19/2034 08:14:24","26dc4851-195f-4ae1-9a19-fbf883bbb35e","48 130 3 131 48 ..."
"EFI_CERT_X509_GUID","sha256RSA","D0B089CE2F5B4DFEFDA59940F7FD852B2CB2A6CB","CN=Trust - Lenovo Certificate","3","CN=Trust - Lenovo Certificate","BC19CCF68446C18B4A08DCE9B1CB4DEB","05/06/2013 20:05:34","05/06/2033 20:05:33","26dc4851-195f-4ae1-9a19-fbf883bbb35e","48 130 3 46 48 ..."
"EFI_CERT_X509_GUID","sha256RSA","46DEF63B5CE61CF8BA0DE2E6639C1019D0ED14F3","CN=Microsoft Corporation UEFI CA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US","3","CN=Microsoft Corporation Third Party Marketplace Root, O=Microsoft Corporation, L=Redmond, S=Washington, C=US","6108D3C4000000000004","06/27/2011 14:22:45","06/27/2026 14:32:45","77fa9abd-0359-4d32-bd60-28f4e78f784b","48 130 6 16 48 ..."
"EFI_CERT_X509_GUID","sha256RSA","580A6F4CC4E4B669B9EBDC1B2B3E087B80D0678D","CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US","3","CN=Microsoft Root Certificate Authority 2010, O=Microsoft Corporation, L=Redmond, S=Washington, C=US","61077656000000000008","10/19/2011 11:41:42","10/19/2026 11:51:42","77fa9abd-0359-4d32-bd60-28f4e78f784b","48 130 5 215 48 ..."
```

### DBX

```
"dbx","LENOVO","30D0S7RX02","FEDCBA9876"
"EFI_CERT_SHA256_GUID","Hash","SignatureOwner"
"EFI_CERT_X509_GUID","SignatureAlgorithmFriendlyName","Thumbprint","Subject","Version","Issuer","SerialNumber","NotBefore","NotAfter","SignatureOwner","RawData"
"EFI_CERT_SHA256_GUID","80B4D96931BF0D02FD91A61E19D14F1DA452E66DB2408CA8604D411F92659F0A","77fa9abd-0359-4d32-bd60-28f4e78f784b"
"EFI_CERT_SHA256_GUID","F52F83A3FA9CFBD6920F722824DBE4034534D25B8507246B3B957DAC6E1BCE7A","77fa9abd-0359-4d32-bd60-28f4e78f784b"
"EFI_CERT_SHA256_GUID","C5D9D8A186E2C82D09AFAA2A6F7F2E73870D3E64F72C4E08EF67796A840F0FBD","77fa9abd-0359-4d32-bd60-28f4e78f784b"
"EFI_CERT_SHA256_GUID","363384D14D1F2E0B7815626484C459AD57A318EF4396266048D058C5A19BBF76","77fa9abd-0359-4d32-bd60-28f4e78f784b"
"EFI_CERT_SHA256_GUID","1AEC84B84B6C65A51220A9BE7181965230210D62D6D33C48999C6B295A2B0A06","77fa9abd-0359-4d32-bd60-28f4e78f784b"
...
"EFI_CERT_SHA256_GUID","10D45FCBA396AEF3153EE8F6ECAE58AFE8476A280A2026FC71F6217DCF49BA2F","77fa9abd-0359-4d32-bd60-28f4e78f784b"
```
