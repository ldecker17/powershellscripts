# Variables
$NTIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$NTPrincipal = New-Object Security.Principal.WindowsPrincipal $NTIdentity
$IsAdmin = $NTPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$Hostversion = "v$($Host.Version.Major).$($Host.Version.Minor)"
$Hostname = $Host.Name
$Console = $Host.UI.RawUI

# Chocolatey profile
$ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path($ChocolateyProfile)) {
  Import-Module "$ChocolateyProfile"
}

# If Admin shell, start on Desktop.
# if ($Host.UI.RawUI.WindowTitle -match "Administrator")
if ($IsAdmin)
{
    Set-Location $HOME\Desktop
}

# Open an Administrative PowerShell window in the current directory
function Enter-Admin
{
    Start-Process PowerShell -Verb RunAs -ArgumentList "-NoExit -c cd '$PWD'"
}

# Directory Listing Aliases
function ll
{
    param ($dir = ".", $all = $false)

    $origFg = $Host.UI.RawUI.ForegroundColor
    $origBg = $Host.UI.RawUI.BackgroundColor
    if ( $all ) { $toList = Get-ChildItem -force $dir }
    else { $toList = Get-ChildItem $dir }

    foreach ($Item in $toList)
    {
        Switch ($Item.Extension)
        {
            ".exe" {$Host.ui.rawui.foregroundColor = "Yellow"}
            ".cmd" {$Host.ui.rawui.foregroundColor = "Red"}
            ".msh" {$Host.ui.rawui.foregroundColor = "Red"}
            ".vbs" {$Host.ui.rawui.foregroundColor = "Red"}
            ".sh" {$Host.ui.rawui.foregroundColor = "Green"}
            ".ps1" {$Host.ui.rawui.foregroundColor = "Green"}
            ".bat" {$Host.ui.rawui.foregroundColor = "Green"}
            ".py" {$Host.ui.rawui.foregroundColor = "Green"}
            ".zip" {$Host.ui.rawui.foregroundColor = "DarkGreen"}
            ".7z" {$Host.ui.rawui.foregroundColor = "DarkGreen"}
            ".rar" {$Host.ui.rawui.foregroundColor = "DarkGreen"}
            ".lnk" {$Host.ui.rawui.foregroundColor = "DarkGray"}
            ".dll" {$Host.ui.rawui.foregroundColor = "DarkGray"}
            Default {$Host.ui.rawui.foregroundColor = $origFg} 
        } 
        if ($Item.Mode.StartsWith("d")) {$Host.ui.rawui.foregroundColor = "DarkCyan"}
        if ($Item.Mode.Substring(0, 4) -like "*h*") {$Host.ui.rawui.foregroundColor = "DarkGray"}
        if ($Item.Mode.Substring(0, 5) -like "*s*") {$Host.ui.rawui.foregroundColor = "Red"}
        $Item
    }
    $Host.UI.RawUI.ForegroundColor = $origFg
    $Host.UI.RawUI.BackgroundColor = $origBg
}

function lla
{
    param ( $dir=".")
    ll $dir $true
}

function la
{
    ll -Force
}

# Windows Update History
function Get-WinUpdates
{
    param( [Parameter(Mandatory=$true)]
    [int] $ResultCode
    )
    $Result = $ResultCode
    switch($ResultCode)
    {
        2
        {
            $Result = "Succeeded"
        }
        3
        {
            $Result = "Succeeded With Errors"
        }
        4
        {
            $Result = "Failed"
        }
    }
    return $Result
}

function Get-ADUserPasswordExpiryTime
{
    [CmdletBinding()]
    param
    (
        [Parameter(
            Mandatory=$true,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)
        ]
        [Alias('User')]
        [ValidateLength(3,30)]
        [String[]]$UserName
    )

    process {
        [System.Collections.ArrayList]$Properties = 'SamAccountName', 'DisplayName', 'PasswordExpired', 'PasswordLastSet', 'msDS-UserPasswordExpiryTimeComputed'
        $UserName | ForEach-Object {
            $ADUser = Get-ADUser -Filter "SamAccountName -eq '$_'" -Properties $Properties
            if ($ADUser) {
                $Properties.Remove('msDS-UserPasswordExpiryTimeComputed')
                $Properties.Add('PasswordExpires') | Out-Null
                $PasswordExpires = [datetime]::FromFileTime($ADUser.'msDS-UserPasswordExpiryTimeComputed')
                $ADUser | Select-Object *, @{
                    Name = 'PasswordExpires'
                    Expression = {$PasswordExpires}
                } | Select-Object $Properties
            }
        }
    }
}

function Get-ADAllUsersPasswordExpiryTime
{
    Get-ADUser -Filter {Enabled -eq $True -and PasswordNeverExpires -eq $False} `
        -Properties DisplayName, msDS-UserPasswordExpiryTimeComputed | `
        Select-Object -Property Displayname,@{Name="Expiration Date";Expression={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}}
}

function Get-ADAllUsersPasswordExpiryTimeSorted
{
    Get-ADUser -Filter {Enabled -eq $True -and PasswordNeverExpires -eq $False} `
        -Properties DisplayName, msDS-UserPasswordExpiryTimeComputed | `
        Select-Object -Property Displayname,@{Name="Expiration Date";Expression={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}} | `
        Sort-Object -Property "Expiration Date"
}

function Get-ADAllUsersPasswordTimeExpired
{
    Get-ADUser -Filter {PasswordExpired -ne $False} `
        -Properties DisplayName, msDS-UserPasswordExpiryTimeComputed | `
        Select-Object -Property Displayname,@{Name="Expiration Date";Expression={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}} | `
        Sort-Object -Property "Expiration Date"
}

# Windows Update History
function Get-WuaHistory
{
    # Get a WUA Session
    $session = (New-Object -ComObject 'Microsoft.Update.Session')
    
    # Query the latest 1000 History starting with the first record.
    $history = $session.QueryHistory("",0,50) | ForEach-Object {
        $Result = Convert-WuaResultCodeToName -ResultCode $_.ResultCode
        
        # Make the properties hidden in com properties visible.
        $_ | Add-Member -MemberType NoteProperty -Value $Result -Name Result
        $Product = $_.Categories | Where-Object {$_.Type -eq 'Product'} | Select-Object -First 1 -ExpandProperty Name
        $_ | Add-Member -MemberType NoteProperty -Value $_.UpdateIdentity.UpdateId -Name UpdateId
        $_ | Add-Member -MemberType NoteProperty -Value $_.UpdateIdentity.RevisionNumber -Name RevisionNumber
        $_ | Add-Member -MemberType NoteProperty -Value $Product -Name Product -PassThru
        
        Write-Output $_
    }
    #Remove null records and only return the fields we want
    $history |
    Where-Object {![String]::IsNullOrWhiteSpace($_.title)} |
    Select-Object Result, Date, Title, SupportUrl, Product, UpdateId, RevisionNumber
}

# Run F7History Script
# Requires PowerShell 6+
if ($Hostversion -ge "v6")
{
    if (Test-Path "$HOME\Documents\WindowsPowerShell\Scripts\F7History.ps1")
    {
        Import-Module Microsoft.PowerShell.ConsoleGuiTools
        & "$HOME\Documents\WindowsPowerShell\Scripts\F7History.ps1"
    }
}

# Aliases
Set-Alias -Name rdns -Value Resolve-DnsName
Set-Alias -Name cdns -Value Clear-DnsClientCache

#Clear-Host