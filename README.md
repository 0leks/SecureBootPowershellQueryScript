
# Overview

This is a utility PowerShell script for investigating SecureBoot UEFI variables.

## Description

It queries the SecureBoot UEFI variables (PK, KEK, DB, DBX) and writes the results to a CSV file for each variable.  
Uses the `Get-SecureBootUEFI` script and some byte wrangling to parse out the relevant information.

## Optional Parameters

`-Path <String>` pk.txt, kek.txt, db.txt, and dbx.txt will be written to Path. Defaults to .\

`-ForAggregation` Appends <Device Manufacturer>\<Device Model>\<Hash of Computer Name> to the output Path

`-Verbose` Enables printing status and error messages to the console.

## Usage Examples

`.\Collect-SecureBootUEFI-Info.ps1`  
`.\Collect-SecureBootUEFI-Info.ps1 -Verbose -ForAggregation -Path ./my_sb_uefi_data`
