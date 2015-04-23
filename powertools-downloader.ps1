#This script is a modified version of a script initially written by Carlos Perez
Remove-Module PowerView -ErrorAction SilentlyContinue
Remove-Module PowerUp -ErrorAction SilentlyContinue
$webclient = New-Object System.Net.WebClient
$url = "https://github.com/Veil-Framework/PowerTools/archive/master.zip"
$file = "$($env:TEMP)\PowerTools.zip"
$webclient.DownloadFile($url,$file)
#Unblock-File -Path $file
$targetondisk = "$([System.Environment]::GetFolderPath('MyDocuments'))\WindowsPowerShell\Modules"
New-Item -ItemType Directory -Force -Path $targetondisk | out-null
$shell_app=new-object -com shell.application
$zip_file = $shell_app.namespace($file)
$destination = $shell_app.namespace($targetondisk)
$destination.Copyhere($zip_file.items(), 0x10)
Rename-Item -Path ($targetondisk+"\PowerTools-master") -NewName "PowerTools" -Force
set-location $targetondisk"\PowerTools\PowerView"; Import-Module .\PowerView
set-location $targetondisk"\PowerTools\PowerUp"; Import-Module .\PowerUp
set-location $targetondisk"\PowerTools\PewPewPew"; Import-Module .\Invoke-MassCommand.ps1, .\Invoke-MassMimikatz.ps1, .\Invoke-MassSearch.ps1, .\Invoke-MassTemplate.ps1, .\Invoke-MassTokens.ps1
