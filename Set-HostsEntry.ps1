<# 
.DESCRIPTION 
Resolve a DNS name to the IPv4 address(es) and update the hosts file with those IP(s). The hostname to resolve is the first parameter of this script,
and the second parameter is the hostname entry you want set for the IP address(es) within the hosts file.
#> 

param (
    [Parameter(Position = 0, Mandatory = $true)]
    [string]$HostToCheck,

    [Parameter(Position = 1, Mandatory = $true)]
    [string]$HostToUpdate
)

$HostPublicIP = (Resolve-DnsName $HostToCheck -QuickTimeout).IP4Address
$hostsFilePath = "C:\Windows\System32\drivers\etc\hosts"

# Read the hosts file content
$hostsFileContent = Get-Content $hostsFilePath

# Find the line containing the hostname
$LineNumber = $hostsFileContent | ForEach-Object { $_.Trim() } | Where-Object { $_ -like "*$HostToUpdate*" } | Select-Object -First 1 | ForEach-Object { $hostsFileContent.IndexOf($_) }

# If a matching line is found, update the IP address
if ($LineNumber -ne $null) {
    $hostsFileContent[$lineNumber] = "$HostPublicIP`t$HostToUpdate"
}
else {
    # If no matching line is found, add a new entry
    $hostsFileContent += "$HostPublicIP`t$HostToUpdate"
}

# Write the updated hosts file content back
$hostsFileContent | Set-Content $hostsFilePath -Force
