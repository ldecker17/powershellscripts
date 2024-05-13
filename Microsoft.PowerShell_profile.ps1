##########
# Variables
##########
$NTIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$NTPrincipal = New-Object Security.Principal.WindowsPrincipal $NTIdentity
$IsAdmin = $NTPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$Hostversion = "$($Host.Version.Major)"
$HostversionMinor = "$($Host.Version.Major).$($Host.Version.Minor)"
$Hostname = $Host.Name
$Console = $Host.UI.RawUI

##########
# Aliases
##########
Set-Alias -Name rdns -Value Resolve-DnsName
Set-Alias -Name rnds -Value Resolve-DnsName
Set-Alias -Name res -Value Resolve-DnsName
Set-Alias -Name cdns -Value Clear-DnsClientCache
Set-Alias -Name tdc -Value Test-DomainConnectivity
Set-Alias -Name tol -Value Test-DomainConnectivity
Set-Alias -Name boot -Value Get-ComputerBootTime
Set-Alias -Name grep -Value Select-String
Set-Alias -Name tc -Value Test-Connection


# Set Auto-complete behavior
Set-PSReadLineKeyHandler -Key Tab -Function MenuComplete
Set-PSReadLineOption -BellStyle Visual
Set-PSReadLineOption -PredictionViewStyle ListView

# If Admin shell, start on Desktop.
# if ($Host.UI.RawUI.WindowTitle -match "Administrator")
if ($IsAdmin) {
    Set-Location $HOME\Desktop
}

# Open an Administrative PowerShell window in the current directory
function Enter-Admin {
    Start-Process wt.exe -Verb RunAs
}

# Directory Listing Aliases
function ll {
    param ($dir = '.', $all = $false)

    $origFg = $Host.UI.RawUI.ForegroundColor
    $origBg = $Host.UI.RawUI.BackgroundColor
    if ( $all ) { $toList = Get-ChildItem -Force $dir }
    else { $toList = Get-ChildItem $dir }

    foreach ($Item in $toList) {
        Switch ($Item.Extension) {
            '.exe' { $Host.ui.rawui.foregroundColor = 'Green' }
            '.cmd' { $Host.ui.rawui.foregroundColor = 'Red' }
            '.msh' { $Host.ui.rawui.foregroundColor = 'Red' }
            '.vbs' { $Host.ui.rawui.foregroundColor = 'Red' }
            '.sh' { $Host.ui.rawui.foregroundColor = 'Green' }
            '.ps1' { $Host.ui.rawui.foregroundColor = 'Green' }
            '.bat' { $Host.ui.rawui.foregroundColor = 'Green' }
            '.py' { $Host.ui.rawui.foregroundColor = 'Green' }
            '.zip' { $Host.ui.rawui.foregroundColor = 'DarkGreen' }
            '.7z' { $Host.ui.rawui.foregroundColor = 'DarkGreen' }
            '.rar' { $Host.ui.rawui.foregroundColor = 'DarkGreen' }
            '.lnk' { $Host.ui.rawui.foregroundColor = 'DarkGray' }
            '.dll' { $Host.ui.rawui.foregroundColor = 'DarkGray' }
            Default { $Host.ui.rawui.foregroundColor = $origFg } 
        } 
        if ($Item.Mode.StartsWith('d')) { $Host.ui.rawui.foregroundColor = 'DarkYellow' }
        if ($Item.Mode.Substring(0, 4) -like '*h*') { $Host.ui.rawui.foregroundColor = 'DarkGray' }
        if ($Item.Mode.Substring(0, 5) -like '*s*') { $Host.ui.rawui.foregroundColor = 'Red' }
        $Item
    }
    $Host.UI.RawUI.ForegroundColor = $origFg
    $Host.UI.RawUI.BackgroundColor = $origBg
}

function lla {
    param ( $dir = '.')
    ll $dir $true
}

function la {
    ll -Force
}

$PSDefaultParameterValues['Get-ADUser:Properties'] = @(
    'DisplayName',
    'Description',
    'EmailAddress',
    'LockedOut',
    'Manager',
    'MobilePhone',
    'telephoneNumber',
    'PasswordLastSet',
    'PasswordExpired',
    'ProxyAddresses',
    'Title',
    'wwWHomePage'
)

function Get-ADUserPasswordExpiryTime {
    [CmdletBinding()]
    param
    (
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)
        ]
        [Alias('User')]
        [ValidateLength(3, 30)]
        [String[]]$UserName
    )

    process {
        [System.Collections.ArrayList]$Properties = 'SamAccountName', 'DisplayName', 'Enabled', 'LockedOut', 'PasswordExpired', 'PasswordLastSet', 'msDS-UserPasswordExpiryTimeComputed'
        $UserName | ForEach-Object {
            $ADUser = Get-ADUser -Filter "SamAccountName -eq '$_'" -Properties $Properties
            if ($ADUser) {
                $Properties.Remove('msDS-UserPasswordExpiryTimeComputed')
                $Properties.Add('PasswordExpires') | Out-Null
                $PasswordExpires = [datetime]::FromFileTime($ADUser.'msDS-UserPasswordExpiryTimeComputed')
                $ADUser | Select-Object *, @{
                    Name       = 'PasswordExpires'
                    Expression = { $PasswordExpires }
                } | Select-Object $Properties
            }
        }
    }
}


function Get-ADAllUsersPasswordExpiryTime {
    Get-ADUser -Filter { Enabled -eq $True -and PasswordNeverExpires -eq $False } `
    -Properties DisplayName, msDS-UserPasswordExpiryTimeComputed | `
    Select-Object -Property Displayname, @{Name = 'Expiration Date'; Expression = { [datetime]::FromFileTime($_.'msDS-UserPasswordExpiryTimeComputed') } } | `
        Sort-Object -Property 'Expiration Date'
    }
    
function Get-ADAllUsersPasswordExpired {
    Get-ADUser -Filter { PasswordExpired -ne $False } `
        -Properties DisplayName, msDS-UserPasswordExpiryTimeComputed | `
        Select-Object -Property Displayname, @{Name = 'Expiration Date'; Expression = { [datetime]::FromFileTime($_.'msDS-UserPasswordExpiryTimeComputed') } } | `
        Sort-Object -Property 'Expiration Date'
}

function Get-ADUserComputers {
    param (
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)
        ]
        [Alias('User')]
        [ValidateLength(3, 30)]
        [String]$UserName
        )

    Get-ADUser $UserName -Server oberon.local -Properties managedObjects | Select-Object managedObjects | Format-List

}

function Get-ADComputerOwner {
    param (
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)
        ]
        [Alias('Computer')]
        [ValidateLength(3, 30)]
        [String]$ComputerName
        )

    Get-ADComputer $ComputerName -Server oberon.local -Properties ManagedBy | Select-Object ManagedBy | Format-List

}


function Get-DnsServers {
    Foreach ( $Interface in (Get-NetIPConfiguration) ) {
        $Order = 1
        Foreach ( $DnsServer in $Interface.DNSServer.ServerAddresses ) {
            [PSCustomObject]@{
                'Interface Alias' = $Interface.InterfaceAlias
                'DNS Server'      = $DnsServer
                'Order'           = $Order
            }
            $Order ++
        }
    }
}

function Test-Ports {

        <#
    .SYNOPSIS
        Tests if defined ports are open.
    .DESCRIPTION
        Test-Ports will check if the entered ports are open at the target
        hostname.
    .NOTES
        This function works on Windows and Linux running PowerShell 7+
    .LINK
        Be sure to check out more PowerShell articles on https://petri.com
    .EXAMPLE
        Test-Ports -Hostname oberontech.com -Ports 443
        Checks if port 443 at oberontech.com is open.
    #>

    param (
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)
        ]
        [Alias('Hostname')]
        [string]$TargetHostname,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 1)
        ]
        [array]$Ports
    )
        if (! $TargetHostname) {
            $Prompt = $host.ui.Prompt("CHECK OPEN PORTS","Enter the hostname and comma separated ports to check: ",@("Hostname","Ports"))
            $Prompt.Ports | ForEach-Object {$Port = $_; if (Test-NetConnection -ComputerName $Prompt.Hostname -Port $Port -InformationLevel Quiet -WarningAction SilentlyContinue) {"Port $Port is open" } else {"Port $Port is closed"} }
        } 
        else {
            $Ports | ForEach-Object {$Port = $_; if (Test-NetConnection -ComputerName $TargetHostname -Port $Port -InformationLevel Quiet -WarningAction SilentlyContinue) {"Port $Port is open" } else {"Port $Port is closed"} }
        }
}


# Winget Autocomplete
Register-ArgumentCompleter -Native -CommandName winget -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)
    [Console]::InputEncoding = [Console]::OutputEncoding = $OutputEncoding = [System.Text.Utf8Encoding]::new()
    $Local:word = $wordToComplete.Replace('"', '""')
    $Local:ast = $commandAst.ToString().Replace('"', '""')
    winget complete --word="$Local:word" --commandline "$Local:ast" --position $cursorPosition | ForEach-Object {
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }
}

# Windows Update History
# Convert Wua History ResultCode to a Name
# 0, and 5 are not used for history
# See https://msdn.microsoft.com/en-us/library/windows/desktop/aa387095(v=vs.85).aspx
function Convert-WuaResultCodeToName {
    param(
        [Parameter(Mandatory = $true)]
        [int] $ResultCode
    )

    $Result = $ResultCode
    switch ($ResultCode) {
        2 {
            $Result = 'Succeeded'
        }
        3 {
            $Result = 'Succeeded With Errors'
        }
        4 {
            $Result = 'Failed'
        }
    }

    return $Result
}

function Get-WinUpdateHistory {

    # Get a WUA Session
    $session = (New-Object -ComObject 'Microsoft.Update.Session')

    # Query the latest 1000 History starting with the first recordp     
    $history = $session.QueryHistory('', 0, 1000) | ForEach-Object {
        $Result = Convert-WuaResultCodeToName -ResultCode $_.ResultCode

        # Make the properties hidden in com properties visible.
        $_ | Add-Member -MemberType NoteProperty -Value $Result -Name Result
        $Product = $_.Categories | Where-Object { $_.Type -eq 'Product' } | Select-Object -First 1 -ExpandProperty Name
        $_ | Add-Member -MemberType NoteProperty -Value $_.UpdateIdentity.UpdateId -Name UpdateId
        $_ | Add-Member -MemberType NoteProperty -Value $_.UpdateIdentity.RevisionNumber -Name RevisionNumber
        $_ | Add-Member -MemberType NoteProperty -Value $Product -Name Product -PassThru

        Write-Output $_
    } 

    # Remove null records and only return the fields we want
    $history | 
    Where-Object { ![String]::IsNullOrWhiteSpace($_.title) } | 
    Select-Object Result, Date, Title, SupportUrl, Product, UpdateId, RevisionNumber
}

function Test-DomainConnectivity {
    Test-NetConnection -InformationLevel Detailed oberon.local
}

function Get-ComputerBootTime {

        $CompInfo = Get-ComputerInfo
        $CompInfo.OsLastBootUpTime

}

# Run F7History Script
# Requires PowerShell 6+
if ($Hostversion -ge 'v6') {
    if (Test-Path "$HOME\Documents\WindowsPowerShell\Scripts\F7History.ps1") {
        Import-Module Microsoft.PowerShell.ConsoleGuiTools
        & "$HOME\Documents\WindowsPowerShell\Scripts\F7History.ps1"
    }
}

# function Get-InstanceID {
#     param (
#         [Parameter(
#             Mandatory=$true,
#             Position=0)
#         ]
#         [Alias('Instance Name')]
#         [ValidateLength(3,30)]
#         [String[]]$INSTANCE_NAME,
#         [Parameter(
#             Position=1)
#         ]
#         [Alias('Region')]
#         [ValidateLength(3,30)]
#         [String[]]$REGION = us-east-1,
#         [Parameter(
#             ValueFromPipeline=$true,
#             ValueFromPipelineByPropertyName=$true,
#             Position=2)
#         ]
#         [Alias('Profile')]
#         [ValidateLength(3,30)]
#         [String[]]$PROFILENAME = Oberon
#     )
    
#     INSTANCE_ID=$(
#     aws ec2 describe-instances --region $REGION --profile $PROFILENAME `
#         --filters "Name=tag:Name,Values=*$INSTANCE_NAME*" `
#         --query 'Reservations[*].Instances[*].InstanceId' `
#         --output text `
#         --no-cli-auto-prompt
#     )
# }

# Chocolatey profile
$ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path($ChocolateyProfile)) {
    Import-Module "$ChocolateyProfile"
}

#################################################
#################################################
# Terminal Shell Integration
# https://learn.microsoft.com/en-us/windows/terminal/tutorials/shell-integration
$Global:__LastHistoryId = -1

function Global:__Terminal-Get-LastExitCode {
    if ($? -eq $True) {
        return 0
    }
    $LastHistoryEntry = $(Get-History -Count 1)
    $IsPowerShellError = $Error[0].InvocationInfo.HistoryId -eq $LastHistoryEntry.Id
    if ($IsPowerShellError) {
        return -1
    }
    return $LastExitCode
}
function prompt {

    if ($Hostversion -ge '6') {
        # First, emit a mark for the _end_ of the previous command.

        $gle = $(__Terminal-Get-LastExitCode)
        $LastHistoryEntry = $(Get-History -Count 1)
        # Skip finishing the command if the first command has not yet started
        if ($Global:__LastHistoryId -ne -1) {
            if ($LastHistoryEntry.Id -eq $Global:__LastHistoryId) {
                # Don't provide a command line or exit code if there was no history entry (eg. ctrl+c, enter on no command)
                $out += "`e]133;D`a"
            }
            else {
                $out += "`e]133;D;$gle`a"
            }
        }


        $loc = $($executionContext.SessionState.Path.CurrentLocation)

        # Prompt started
        $out += "`e]133;A$([char]07)"

        # CWD
        $out += "`e]9;9;`"$loc`"$([char]07)"

        # (your prompt here)
        $out += "PWSH $loc$('>' * ($nestedPromptLevel + 1)) "

        # Prompt ended, Command started
        $out += "`e]133;B$([char]07)"

        $Global:__LastHistoryId = $LastHistoryEntry.Id

        return $out
    }
}

#################################################
#################################################
#34de4b3d-13a8-4540-b76d-b9e8d3851756 PowerToys CommandNotFound module

Import-Module "c:\program files\powertoys\WinUI3Apps\..\WinGetCommandNotFound.psd1"
#34de4b3d-13a8-4540-b76d-b9e8d3851756
