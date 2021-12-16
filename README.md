
This is a utility PowerShell script for investigating SecureBoot UEFI variables.

It queries the SecureBoot UEFI variables (PK, KEK, DB, DBX) and writes the results to a CSV file for each variable.
Uses the Get-SecureBootUEFI script and some byte wrangling to parse out the relevant information.

## Optional Parameters

-Path <String>
	pk.txt, kek.txt, db.txt, and dbx.txt will be written to Path. Defaults to .\

-ForAggregation [<SwitchParameter>]
	Appends <Device Manufacturer>\<Device Model>\<Hash of Computer Name> to the output Path

-Verbose [<SwitchParameter>]
	Enables printing status and error messages to the console.
