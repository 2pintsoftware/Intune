<# 
   .SYNOPSIS 
    Checks Branchcache is Using Desired Port and that the service is running

   .DESCRIPTION
    1. Checks for event 7,8 in the BC event log - means that F/W is blocking BC
    2. Checks that the Branchcache has been configured to use a specificTCP port
    3. Checks  the Branchcache Cache TTL value
    4. Checks that the BranchCache service is set to 'Distributed Caching' mode
    5. Checks the 'serve peers on battery power' capability
    6. Finally - checks that the service is running and is set to AutoStart
    7. If ANY of these checks fail - a status of Non-Compliance is reported 
    8. Creates a Logfile in the C:\Windows\Temp folder


NOTES
    AUTHOR: 2Pint Software
    EMAIL: support@2pintsoftware.com
    TUNER VERSION: 1.0.2.0
    DATE: 20 May 2022
    
    CHANGE LOG: 
    1.0.0.0 : 12/10/2017  : Initial version of script 
    1.0.0.2 : 12/10/2017  : added logging and other minor tweaks
    1.0.0.3 : 08/06/2018  : added some more logic for checking svc auto-start and state..
    1.0.0.4 : 09/06/2018  : consolidated the 'Serve Peers on Battery' and 'Cache TTL' check into this script
    1.0.0.5 : 26/06/2018  : Added BranchCache Firewall Error Event check
    1.0.0.6 : 23/07/2019  : Improved Port compliance checking
    1.0.0.7 : 12/08/2019  : Improved Port checking - added ConnectPort (we were only checking ListenPort before)
    1.0.0.8 : 8/7/2020    : Added support for Windows Server and improved logging
    1.0.0.9 : 5/3/2021    : Added support for non-English languages
    1.0.1.0 : 23/3/2021   : Added another check for firewall issues using netsh
    1.0.2.0 : 20/05/2022  : Intune Proactive Remediation version ONLY

   .LINK
    https://2pintsoftware.com
#>

$Logfile = "C:\Windows\Temp\Detect_BC_Status.log"

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

Write-Log "BC Port, Firewall and Service Check is Running"

# Set this variable to the port number that you wanna check/change - if you want to leave it at the default BC port you MUST set this to 80
# THIS SHOULD BE THE SAME AS THE EQUIVALENT VARIABLE IN THE REMEDIATION SCRIPT
#--------------
$BCPort = 1337
#--------------
# SET THIS VARIABLE TO DETERMINE IF CLIENTS CAN SERVE PEERS WHILE ON BATTERY POWER
#--------------
$ServeOnBattery = "TRUE"
#--------------

# Set this variable to check the cache TTL  - this is the time (Days) that BranchCache will keep content in the cache
#-----------------------
$TTL = 180
#-----------------------

#================================================================
#check if the stifler client is present
#================================================================
$SearchString = "StifleR Client"
     $path = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
              )                
$StifCliVer = Get-ChildItem $path -ErrorAction SilentlyContinue -Force |
    Get-ItemProperty |
            Where-Object {$_.DisplayName -match $SearchString } |
                        Select-Object -Property VersionMajor, VersionMinor

#if the stifler client (2.7 or higher) IS present AND running we have nothing to do here as the StifleR Client will perform the remediation
#so we will log this and exit
If (($StifCliVer.VersionMajor -ge 2) -and ($StifCliVer.VersionMinor -ge 7)) {
$s = gcim -Query "Select State, StartMode From Win32_Service Where Name='stiflerclient'"
if ($s.State -eq "Running"){
Write-Log "StifleR 2.7 or higher is present and running - remediation not required, exiting"
Exit 0}
}
#================================================================
#END Stifler Client check
#If no StifleR client - we can proceed
#================================================================

# First we assume the client is compliant
$Compliance = "Compliant"

#================================================================
# If Windows Server, check if BranchCache feature has been added
#================================================================

$OSCaption = (Get-WmiObject win32_operatingsystem).caption
If ($OSCaption -like "*Windows Server*"){
    Write-Log "OS is a server, check for BranchCache feature" 
    $Result=Get-WindowsFeature BranchCache

    If($Result.Installed -eq $true){
        $Compliance = "Compliant"
    }
    Else{
        $Compliance = "Feature Check Non-Compliant"
        Write-Log "BC Feature Check - failed" 
        Write-Log "Feature Check Returned - $Compliance"
        Write-Log "Remediation required, exiting"
        Exit 1
    }
}



#================================================================
# Check the event log for events 7,8 - meaning that BC+P2P is blocked
#================================================================

$EventLogName = "Microsoft-Windows-BranchCache/Operational"

# Check if the BC evt log exists and returns a result (or evt 7 or 8) - if not - then we are Compliant
$log = try{ 
Get-WinEvent -LogName $EventLogName -ErrorAction Stop | Where-Object {$_.ID -eq 7 -or $_.ID -eq 8} 
          }

catch {
    Write-log "No BC event log found or the log is empty" 
      }


# If no results then we are compliant (either no log found or no results returned)
if (!$log){
    $Compliance = "Compliant"
}
# If the above query returns a result - set the status to Non-Compliant 
Else{
    $Compliance = "BC Event Log (Firewall related events) Check Non-Compliant"
    Write-Log "BC Firewall Events check - failed" 
    Write-Log $Compliance
    Write-Log "Remediation required, exiting" 
    Write-OUtput "BC Event log shows Firewall errors - remediation required"
    Exit 1
}

Write-Log "BC Firewall Event Log Check Returned - $Compliance"

#=========================================================
# Next Check that the netsh output for the firewall is ok
#=========================================================

# Call netsh to carry out a match against the status
$ShowStatusAllCommand = {netsh branchcache show status all}
$ShowStatusAll = Invoke-Command -ScriptBlock $ShowStatusAllCommand
$ShowStatusAllMsg = $ShowStatusAll | Out-String
Write-Log "netsh (show status all) output:"
Write-Log $ShowStatusAllMsg

$fw = try{
($ShowStatusAll | Select-String -SimpleMatch -Pattern "Error Executing Action Display Firewall Rule Group Status:")[0].ToString() -match "Could not query Windows Firewall configuration"
         }
catch [Exception]{
    if (($_.Exception -match "You cannot call a method on a null-valued expression") -or ($_.Exception -match "Cannot index into a null array")){
    
    }
    Else {Write-Log $_.Exception}
}

$fw = try{
($ShowStatusAll | Select-String -SimpleMatch -Pattern "Warning:")[0].ToString() -match "An HTTP URL Reservation is required but not configured"
         }
catch [Exception]{
    if (($_.Exception -match "You cannot call a method on a null-valued expression") -or ($_.Exception -match "Cannot index into a null array")){
    
    }
    Else {Write-Log $_.Exception}
}

# If no results then we are compliant (no firewall error )
if (!$fw){
    $Compliance = "Compliant"
    Write-Log "No NETSH config issues reported"
         }
# If the above query returns a result - set the status to Non-Compliant 
Else{
    $Compliance = "Netsh output Non-Compliant"
    Write-Log "BranchCache not setup correctly " 
    Write-Log "Netsh.exe Check Returned - $Compliance"
    Write-Log "Remediation required, exiting"
    Write-OUtput "Netsh output show an error - remediation required"
    Exit 1
    }

Write-Log "BC Firewall netsh Check Returned - $Compliance"

#=========================================================
# Call netsh to carry out a match against the status
#=========================================================
$ShowHttpUrl = netsh http show url
# Checking the port has been set - for both listen and connect ports
$BCUrlRes = $myvar = [bool]($ShowHttpUrl | Select-String -SimpleMatch -Pattern "http://+:$BCPort/116B50EB-ECE2-41ac-8429-9F9E963361B7/")
$BCListenPortReg = ((Get-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PeerDist\DownloadManager\Peers\Connection' -Name ListenPort -ErrorAction SilentlyContinue).ListenPort) -eq $BCPort
$BCConnectPortReg = ((Get-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PeerDist\DownloadManager\Peers\Connection' -Name ConnectPort -ErrorAction SilentlyContinue).ConnectPort) -eq $BCPort

if($BCUrlRes -eq $true -and $BCListenPortReg -eq $true -and $BCConnectPortReg -eq $true){
    $Compliance = "Compliant"
}
else{
    $Compliance = "BranchCache Port Non-Compliant"
    Write-Log "BC Service correct Listening or Connect Port not set"
    Write-Log "BC Port Check Returned - $Compliance"
    Write-Log "Exiting here - remediation required"
    Write-OUtput "BC Service Port or URL Reservation not set - remediation required"
    Exit 1
}

Write-Log "BC Port Check Returned - $Compliance"

#=========================================================
#Next Check that the BranchCache Cache TTL is set correctly
#=========================================================

if((Get-ItemProperty -path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\PeerDist\Retrieval' -Name SegmentTTL -ErrorAction SilentlyContinue).SegmentTTL -eq $TTL){
    $Compliance = "Compliant"
}
else{
    $Compliance = "BC Cache TTL Non-Compliant"
    Write-Log "BC Cache TTL not setup correctly"
    Write-Log "BC Cache TTL Check Returned - $Compliance"
    Write-Log "Exiting here - remediation required"
    Write-OUtput "BC Cache TTL not setup correctly - remediation required"
    Exit 1
}

Write-Log "BC Cache TTL Check Returned - $Compliance"

#=========================================================
# Next Check that the BranchCache service is enabled and set to Distributed Caching
#=========================================================

# Call netsh to carry out a match against the status
$ShowStatusCommand = {netsh branchcache show status}
$ShowStatus = Invoke-Command -ScriptBlock $ShowStatusCommand
$ShowStatusMsg = $ShowStatus | Out-String
WRite-Log "netsh output:"
Write-Log $ShowStatusMsg
# Checking status - if the previous check for BC Cache TTL was Compliant AND the service is setup correctly - we're OK
if((@($ShowStatus | Select-String -SimpleMatch -Pattern "Distributed Caching")[0].ToString() -match "Distributed Caching") -and ($Compliance -eq "Compliant")){

    $Compliance = "Compliant"
}
else{
    $Compliance = "BC Mode Non-Compliant"
    Write-Log "BC Service not setup correctly " 
    Write-Log "BC Svc Distributed Mode Check Returned - $Compliance"
    Write-Log "Exiting here - remediation required"
    Write-OUtput "BC Service not setup correctly - remediation required"
    Exit 1
}

Write-Log "BC Svc Distributed Mode Check Returned - $Compliance"

#=========================================================
# Next Check the BranchCache SERVE ON BATTERY is set to your preferred setting
#=========================================================

switch ($ServeOnBattery){
    TRUE {$ServeOnBattery = 1}
    FALSE{$ServeOnBattery = 0}
}

if((Get-ItemProperty -path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\PeerDist\DownloadManager\Upload' -Name ServePeersOnBatteryPower -ErrorAction SilentlyContinue).ServePeersOnBatteryPower -eq $ServeOnBattery){
    $Compliance = "Compliant"
}
else{   
    $Compliance = "BC Battery Mode Non-Compliant"
    Write-Log "BC Serve Peers on Battery not setup correctly "
    Write-Log "BC Battery Check Mode Check Returned - $Compliance"
    Write-Log "Exiting here - remediation required"
    Write-OUtput "BC Serve Peers on Battery not setup correctly - remediation required"
    Exit 1
}

Write-Log "BC Battery Check Mode Check Returned - $Compliance"

#=========================================================
# Finally check the branchcache service is started and is set to auto-start
#=========================================================
$s = gwmi -Query "Select State, StartMode From Win32_Service Where Name='peerdistsvc'"

if (($s.StartMode -eq "Auto") -and ($s.State -eq "Running")){
    $Compliance = "Compliant"
}
else{
    $Compliance = " BC Svc State Non-Compliant"
    Write-Log "BC Service not set to Autostart " 
    Write-Log "BC Svc startup Check Returned - $Compliance"
    Write-Log "Exiting here - remediation required"
    Write-OUtput "BC Service not set to Autostart - remediation required"
    Exit 1
}


Write-Log "BC Svc startup Check Returned - $Compliance"
#If we made it here all checks were ok so we can return 0
    Write-Log "Exiting script - no remediation required"
    Write-Output "Exiting detection script - no remediation required"
Exit 0
