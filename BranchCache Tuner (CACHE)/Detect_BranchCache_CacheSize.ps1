<# 
   .SYNOPSIS 
    Checks size of branchcache cache

   .DESCRIPTION
    Checks that the current size of the branch cache is still correct 
     Note  that the default in this script are fairly conservative - so feel free to be more agressive with the cache size!

   .NOTES
    AUTHOR: 2Pint Software
    EMAIL: support@2pintsoftware.com
    TUNER VERSION: 1.0.1.0
    DATE:22 May 2022
    
    CHANGE LOG: 
    1.0.0.0 : 12/10/2017  : Initial version of script 
    1.0.0.2 : 10/06/2018  : Added a bit more logging
    1.0.0.3 : 8/7/2020    : Added support for Windows Server and improved logging
    1.0.0.4 : 5/3/2021    : Changes to support non-English languages
    1.0.1.0 : 22/05/2022  : Intune Proactive Remediation version


   .LINK
    https://2pintsoftware.com
#> 


$Logfile = "C:\Windows\Temp\Detect_BranchCache_CacheSize.log"

# Delete any existing logfile older than 5 mins if it exists (because the detect script runs immediately after the remediation script
# so we don't want it to be deleted until the next time it runs)
If (Test-Path $Logfile)
{
$Mins = "-5"
$CurrentDate = Get-Date
$DatetoDelete = $CurrentDate.AddMinutes($Mins)
Get-ChildItem $Logfile | Where-Object { $_.LastWriteTime -lt $DatetoDelete } | Remove-Item -Force -ErrorAction SilentlyContinue -Confirm:$false
}

Function Write-Log{
	param (
    [Parameter(Mandatory = $true)]
    [string]$Message
   )

   $TimeGenerated = $(Get-Date -UFormat "%D %T")
   $Line = "$TimeGenerated : $Message"
   Add-Content -Value $Line -Path $LogFile -Encoding Ascii

}

#=======================================
# Get the free space on the system disk as %
#=======================================
Function Get-FreeSystemDiskspace{
    # Get the free space from WMI and return as %
    $SystemDrive = Get-WmiObject Win32_LogicalDisk  -Filter "DeviceID='$env:SystemDrive'"
    [int]$ReturnVal = $Systemdrive.FreeSpace*100/$Systemdrive.Size
    return $ReturnVal
}
#==============
# End Function
#==============

#=============================================================================
# Selects the best cache size based on free diskspace - EDIT THE DEFAULTS HERE
#=============================================================================
Function Check-BranchCachesize{
    param([int]$CurrentFreeSpace)
    begin{
        switch($CurrentFreeSpace){
            {$_ -lt 10 -and $_ -ge 5}{$NewCachePercent = 5} #if less than 10% but more than 5% new cache should be 5%
            {$_ -lt 50 -and $_ -ge 10}{$NewCachePercent = 10} #if less than 50%  but more than 10% new cache should be 10%
            {$_ -lt 75 -and $_ -ge 50}{$NewCachePercent = 20}##if less than 75% but more than 50% new cache should be 20%
            {$_ -ge 75}{$NewCachePercent = 50}##if more than 75% new cache should be 50%
            default{$NewCachePercent = 5}#default value
        }
    Return $NewCachePercent
    }
}
#==============
# End Function
#==============
Write-Log "BC Cache Size Check is Running"

# First we assume the client is compliant
$Compliance = "Compliant"

#==============================================================
# Get the size available and then return the cache space needed
#==============================================================
$FreeSpaceAvailable = Get-FreeSystemDiskspace
$CacheSize  = Check-BranchCachesize -CurrentFreeSpace $FreeSpaceAvailable

Write-Log "Free Space Check Returned: $FreeSpaceAvailable %"
Write-Output "Free Space Check Returned: $FreeSpaceAvailable %" 
Write-Log "BranchCache Cache size should be: $CacheSize %"
Write-Output "BranchCache Cache size should be: $CacheSize %"

#==============================================================
# Call netsh to carry out a match against the status
#==============================================================
Write-Log "Checking current Cache size by running netsh cmd"
Write-Log "netsh output:"
$ShowStatusLocalCmd = {netsh branchcache show localcache}
$ShowStatus = Invoke-Command -ScriptBlock $ShowStatusLocalCmd
#need to convert the array to string for the logging
$ShowStatusString = $ShowStatus | Out-String
Write-Log $ShowStatusString

# Checking cache size has been set
if(@($ShowStatus | Select-String -SimpleMatch -Pattern "%")[0].ToString() -match "$CacheSize%")
{
    $Compliance = "Compliant"
    Write-Log "BC Cache Size Check Returned: $Compliance"
    Write-Log "Exiting with no remediation required"
    Write-Output "Exiting with no remediation required"
    Exit 0
}
else
{
    $Compliance = "Non-Compliant"
    Write-Log "BC Cache Size Check Returned: $Compliance"
    Write-Log "Exiting with remediation required"
    Write-Output "Exiting with remediation required"
    Exit 1
}

