<# 
   .DISCLAIMER 
   Please use at your own risk. 2Pint Software provide this script 'as is'
   and it should be thoroughly tested before deployment in your production environment. 
   
   
   .SYNOPSIS 
    Remediate Branchcache port and configures that branchcache service
    Please note this is the Intune Proactive Remediation version

   .DESCRIPTION
    1. Set the required Port Number for P2P transfers
    2. Configure the BranchCache Service for Distributed MOde
    3. Delete the old reservation on port 80 if it's still there
    4. Sets the Cache data TTL value
    5. Configures the BC service to Autostart and starts it
    6. Configures the Windows Firewall
    7. Creates a Logfile in the C:\Windows\Temp folder



    AUTHOR: 2Pint Software
    EMAIL: support@2pintsoftware.com
    TUNER VERSION: 1.0.2.0
    DATE: 20 May 2022 
    
    CHANGE LOG: 
    1.0.0.0 : 12/10/2017  : Initial version of script 
    1.0.0.2 : 12/10/2017  :  added check for the old port 80 reservation -  deletes it if exist
    1.0.0.3 : 12/10/2017  :  Sets firewall rules to the correct port - SCCM can create multiple rules which aren't all set by default
    1.0.0.4 : 12/10/2017  :  Consolidated the Port Check and service check into one to reduce errors
    1.0.0.5 : 12/10/2017  :  Added Battery Check 'Serve Peers on Battery' - set to TRUE/FALSE
    1.0.0.6 : 09/06/2018  : Changed the order of things and added a service stop. Also added Cache TTL
    1.0.0.7 : 14/08/2018  : Removes all BC Firewall Rules first - and then re-adds them later. Also removes Hosted Cache Rules.
    1.0.0.8 : 16/08/2018  : Added a check to see if the Windows Firewall is in play - if not - no point fiddling!
    1.0.0.9 : 23/07/2019  : Improved url reservation handling - changed the order a little
    1.0.1.0 : 12/08/2019  : Improved url reservation handling to remove old url if the port is changed
    1.0.1.1 : 8/7/2020    : Added support for Windows Server and improved logging
    1.0.1.2 : 5/3/2021    : Added support for non-English languages and added a 'clear event log' step
    1.0.1.3 : 23/3/2021   : Remove Firewall detection as it has proved unreliable
    1.0.2.0 : 20/05/2021  : Intune proactive Remediation version - added check for the StifleRClient version. If > 2.7 abort script.

   .LINK
    https://2pintsoftware.com
#>

$Logfile = "C:\Windows\Temp\Remediate_BC_Status.log"

# Delete any existing logfile if it exists
If (Test-Path $Logfile){Remove-Item $Logfile -Force -ErrorAction SilentlyContinue -Confirm:$false}

Function Write-Log{
	param (
    [Parameter(Mandatory = $true)]
    [string]$Message
   )

   $TimeGenerated = $(Get-Date -UFormat "%D %T")
   $Line = "$TimeGenerated : $Message"
   Add-Content -Value $Line -Path $LogFile -Encoding Ascii
   Write-Output $Line

}

# EDIT THIS VARIABLE TO THE PORT THAT YOU WANT BRANCHCACHE TO USE
# THIS SHOULD BE THE SAME AS THE EQUIVALENT IN THE DISCOVERY SCRIPT
#--------------<<<<<
$BCPort = 1337
#--------------<<<<<
# SET THIS VARIABLE TO DETERMINE IF CLIENTS CAN SERVE PEERS WHILE ON BATTERY
# TRUE/FALSE
#-----------------------<<<<<
$ServeOnBattery = "TRUE"
#-----------------------<<<<<

# SET THIS VARIABLE to set the TTL  - this is the time (Days) that BranchCache will keep content in the cache
#-----------------------<<<<<
$TTL = 180
#-----------------------<<<<<

$RegPath = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\PeerDist\DownloadManager\Peers\Connection'
$TTLRegPath = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\PeerDist\Retrieval'
$SetBCCommand = {netsh branchcache set service mode=distributed serveonbattery=$ServeOnBattery}
$ShowHttpUrl = netsh http show url
$DeleteResCmd = {netsh http delete urlacl url=$urlToDelete}
$DisableBCCommand = {netsh branchcache set service mode=disabled}

Write-Log "BC Port, Firewall and Service Remediation is Running"

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
Write-Log "StifleR 2.7 or higher is present and running so quitting"
Exit 0}
}
Else {Write-Log "StifleR 2.7 (or above) Client not present"}
#================================================================
#END Stifler Client check
#If no StifleR client - we can proceed
#================================================================




#================================================================
# If Windows Server, add BranchCache feature if not installed
#================================================================

$OSCaption = (Get-WmiObject win32_operatingsystem).caption
If ($OSCaption -like "*Windows Server*"){
    Write-Log "OS is a server, check for BranchCache feature"
    $Result=Get-WindowsFeature BranchCache

    If($Result.Installed -eq $true){
        Write-Log "BranchCache feature found, all ok, continuing" 
    }
    Else{
        Write-Log "BranchCache feature not found, adding it" 
        Install-WindowsFeature BranchCache
    }
}


#---------------------------------------------------------------------------------------
# Stop BranchCache (Only if installed) 
#---------------------------------------------------------------------------------------
Write-Log "Stopping the BranchCache Service"

$s = Get-Service -name PeerDistSvc -ErrorAction SilentlyContinue

If ($s){
    Stop-Service $s.name -Force
       }
Write-log "BranchCache svc is $($s.Status)"

#---------------------------------------------------------------------------------------
# Set the correct BranchCache ListenPort in the registry
#---------------------------------------------------------------------------------------

Write-Log "Setting ConnectPort and ListenPort reg keys & values"
# If the key doesn't exist - create it, and set the ports

If (!(Test-Path $RegPath))
{
Write-Log "Creating Registry key:$RegPath"
New-Item -Path $RegPath -Force | Out-Null
Write-Log "Setting the value for Listenport to:$BCPort" 
New-ItemProperty -Path $RegPath -Name ListenPort -PropertyType DWORD -Value $BCPort
Write-Log "Setting the value for Connectport to:$BCPort"
New-ItemProperty -Path $RegPath -Name ConnectPort -PropertyType DWORD -Value $BCPort
}

# If the root reg key exists but the values don't we fix that
if(!(Get-ItemProperty -path $RegPath -Name ListenPort -ErrorAction SilentlyContinue))
{
Write-Log "Creating Listenport Reg value"
New-ItemProperty -Path $RegPath -Name ListenPort -PropertyType DWORD -Value $BCPort
}

if(!(Get-ItemProperty -path $RegPath -Name ConnectPort -ErrorAction SilentlyContinue))
{
Write-Log "Creating Connectport Reg value"
New-ItemProperty -Path $RegPath -Name ListenPort -PropertyType DWORD -Value $BCPort
}

# If the Listenport values already exist, check the value and change if required
if((Get-ItemProperty -path $RegPath -Name ListenPort -ErrorAction SilentlyContinue).ListenPort -ne $BCPort){
    Write-Log "Custom BC ListenPort Reg value exists but is incorrect - remediating"
    Set-ItemProperty -Path $RegPath -Name ListenPort -Value $BCPort
}

# If the Connectport value already exists, check the value and change if required
if((Get-ItemProperty -path $RegPath -Name ConnectPort -ErrorAction SilentlyContinue).ConnectPort -ne $BCPort){
    Write-Log "Custom BC ConnectPort Reg value exists but is incorrect - remediating"
    Set-ItemProperty -Path $RegPath -Name ConnectPort -Value $BCPort
}



#---------------------------------------------------------------------------------------
# Set the correct TTL - this is the time (Days) that BranchCache will keep content in the cache
#---------------------------------------------------------------------------------------
# If the key doesn't exist - create it, and set the TTL, job done
If (!(Test-Path $TTLRegPath)) {New-Item -Path $TTLRegPath -Force | Out-Null
                               New-ItemProperty -Path $TTLRegPath -Name SegmentTTL -PropertyType DWORD -Value $TTL
                              }

# If the key already exists, check the value and change if required
if(((Get-ItemProperty -path $TTLRegPath -Name SegmentTTL -ErrorAction SilentlyContinue).SegmentTTL) -ne $TTL){
    Set-ItemProperty -Path $TTLRegPath -Name SegmentTTL -Value $TTL  
}

Write-Log "BranchCache TTL Remediation Complete"


#---------------------------------------------------------------------------------------
# Remove existing F/W Rules (if it's enabled) in case they are a mess!
#---------------------------------------------------------------------------------------

    Write-Log "Removing old F/W Rules"

    #Remove Content Retrieval Rules (IN/OUT)
    netsh advfirewall firewall delete rule name="BranchCache Content Retrieval (HTTP-Out)"
    netsh advfirewall firewall delete rule name="BranchCache Content Retrieval (HTTP-In)"

    #Remove Content Discovery Rules (IN/OUT)
    netsh advfirewall firewall delete rule name="BranchCache Peer Discovery (WSD-Out)"
    netsh advfirewall firewall delete rule name="BranchCache Peer Discovery (WSD-In)"


#---------------------------------------------------------------------------------------
# END Remove existing F/W Rules in case they are a mess!
#---------------------------------------------------------------------------------------

#---------------------------------------------------------------------------------------
# Enable BranchCache distributed mode (this also sets the correct 'Serve Peers on Battery' Mode)
# It will also re-create the F/W Rules
#---------------------------------------------------------------------------------------
Write-Log "Setting BranchCache service to Distributed Mode"
Write-Log "Setting BranchCache 'Serve Peers on Battery' Mode"
Invoke-Command -ScriptBlock $SetBCCommand

#---------------------------------------------------------------------------------------
# Clear the BC Event Log so that subsequent discoveries don't pickup old events
#---------------------------------------------------------------------------------------
Write-Log "Clearing the Event Log"
Function Clear-WinEvent { 
[CmdletBinding(SupportsShouldProcess=$True)]
Param
([String]$LogName)
Process {
If ($PSCmdlet.ShouldProcess("$LogName", "Clear log file")) 
              {
[System.Diagnostics.Eventing.Reader.EventLogSession]::`
GlobalSession.ClearLog("$LogName")
              } # End of If
        } # End of Process
} # End of creating the function

# Calling the function Clear-WinEvent 
#Clear-Host
$BCLog = "Microsoft-Windows-BranchCache/Operational"
Get-WinEvent -ListLog $BCLog
Clear-WinEvent -LogName $BCLog


#---------------------------------------------------------------------------------------
# Set the service to auto-start and start it if not running
#---------------------------------------------------------------------------------------
Write-Log "Setting BranchCache service to Auto-start"
Set-Service -Name "peerdistsvc" -StartupType automatic
if ((Get-Service -Name PeerDistSvc).Status -ne "Running"){
    Start-Service -Name PeerdistSvc
}

#---------------------------------------------------------------------------------------
# Remove the old existing URL reservation i.e remove any BranchCache url reservation that DOES NOT have the current Port
#---------------------------------------------------------------------------------------

# Checking for old obsolete port reservations - first, select all BranchCache url reservations
$ResList = ($ShowHttpUrl | Select-String -SimpleMatch -Pattern "/116B50EB-ECE2-41ac-8429-9F9E963361B7/")
Write-Log "Current URL Reservations: $Reslist"

ForEach($Res in $ResList){

    $a = [regex]::Matches($Res, 'http(.*)')
    If($a -like "http://+:$BCPort*"){
        Write-Log "Not deleting the current URL: $a"
    }
    else{
        $urlToDelete=$a.Value.Trim()
                Write-Log "Deleting the URL: $a"
        Invoke-Command -scriptblock $DeleteResCmd | Out-File $Logfile -Append 
    }
 
}
