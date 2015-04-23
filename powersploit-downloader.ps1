#This script is a modified version of a script initially written by Carlos Perez
Remove-Module PowerSploit -ErrorAction SilentlyContinue
$webclient = New-Object System.Net.WebClient
$url = "https://github.com/mattifestation/PowerSploit/archive/master.zip"
$file = "$($env:TEMP)\PowerSploit.zip"
$webclient.DownloadFile($url,$file)
#Unblock-File -Path $file
$targetondisk = "$([System.Environment]::GetFolderPath('MyDocuments'))\WindowsPowerShell\Modules"
New-Item -ItemType Directory -Force -Path $targetondisk | out-null
$shell_app=new-object -com shell.application
$zip_file = $shell_app.namespace($file)
$destination = $shell_app.namespace($targetondisk)
$destination.Copyhere($zip_file.items(), 0x10)
Rename-Item -Path ($targetondisk+"\PowerSploit-master") -NewName "PowerSploit" -Force
set-location $targetondisk"\PowerSploit"; Import-Module .\PowerSploit
