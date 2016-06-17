#Requires -version 3
#
Function Get-HttpSecHead
{
    <#
            .Synopsis
            Retrieve HTTP Headers from target webserver
            .Description
            This cmdlet will get the HTTP headers from the target webserver and test for the presence of various security related HTTP headers and also display the cookie information.
            .Parameter url
            The target http or https link
            .Parameter log
            This is a switch to provide a log of the output from the script, via the Start-Transcript cmdlet. The log file is stored in the working directory.
            .Parameter cred
            This is a switch to provide the ability to log into a website before accessing the headers, this is sometimes a requirement for development websites that are hidden behind some sort of logon requirement ie BAsic Auth.


            Written by Dave Hardy, davehardy20@gmail.com @davehardy20
            with consultancy from Mike Woodhead, @ydoow

            Version 0.9

            .Example
            PS C:> Get-Httphead -url https://www.linkedin.com

            Header Information for https://www.linkedin.com

            Key                       Value                                                                                                                                            
            ---                       -----                                                                                                                                            
            X-FS-UUID                 2f90ea20d61c281480616685e02a0000                                                                                                                 
            X-Page-Speed              1                                                                                                                                                
            X-Frame-Options           sameorigin                                                                                                                                       
            X-Content-Type-Options    nosniff                                                                                                                                          
            X-Li-Fabric               prod-ltx1                                                                                                                                        
            Strict-Transport-Security max-age=0                                                                                                                                        
            Content-Type              text/html; charset=utf-8                                                                                                                         
            Date                      Sun, 10 Jan 2016 16:16:25 GMT                                                                                                                    
            Set-Cookie                lang="v=2&lang=en-us"; Path=/; Domain=linkedin.com,JSESSIONID="ajax:3001827061456051750"; Path=/; Domain=.www.linkedin.com,bcookie="v=2&52f4f9...
            Server                    Play                                                                                                                                             
            Pragma                    no-cache                                                                                                                                         
            Expires                   Thu, 01 Jan 1970 00:00:00 GMT                                                                                                                    
            Cache-Control             no-cache, no-store                                                                                                                               
            Transfer-Encoding         chunked                                                                                                                                          
            Connection                keep-alive                                                                                                                                       
            X-Li-Pop                  prod-tln1                                                                                                                                        
            X-LI-UUID                 L5DqINYcKBSAYWaF4CoAAA==                                                                                                                         




            HTTP security Headers
            Consider adding the values in RED to improve the security of the webserver. 

            X-XSS-Protection Header MISSING
            Strict-Transport-Security Header PRESENT
            Content-Security-Policy Header MISSING
            X-Frame-Options Header PRESENT
            X-Content-Type-Options Header PRESENT
            Public-Key-Pins Header MISSING


            Cookies Set by https://www.linkedin.com
            Inspect cookies that don't have the HTTPOnly and Secure flags set.


            JSESSIONID = "ajax:3001827061456051750"
            HTTPOnly Flag Set = False
            Secure Flag Set = False
            Domain = .www.linkedin.com 

            bscookie = "v=1&2016011016162553e9dcc3-2b9c-46f0-8256-567060481ba9AQGtXnXhM9bGqUX1OCg2nZArYZ1-q22J"
            HTTPOnly Flag Set = True
            Secure Flag Set = True
            Domain = .www.linkedin.com 

            lang = "v=2&lang=en-us"
            HTTPOnly Flag Set = False
            Secure Flag Set = False
            Domain = linkedin.com 

            bcookie = "v=2&52f4f98f-4b03-4e76-8108-fa64943e23b8"
            HTTPOnly Flag Set = False
            Secure Flag Set = False
            Domain = .linkedin.com 

            lidc = "b=TGST09:g=9:u=1:i=1452442585:t=1452528985:s=AQFBgd0U4ooKN78d-Y-oP4EqatEQQgfe"
            HTTPOnly Flag Set = False
            Secure Flag Set = False
            Domain = .linkedin.com 


    #>
    [cmdletbinding()]
    Param
    (
        [Parameter(Position = 0,Mandatory = $true,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'The URL for inspection, e.g. https://www.linkedin.com')]
        [ValidateNotNullorEmpty()]
        [Alias('link')]
        [string]$url,

        
        [Parameter(Position = 1,Mandatory = $false,
        HelpMessage = "Log the script's output to a logfile")]
        [ValidateSet('y','Y','yes','Yes','YES')]
        [string]$log,


        [Parameter(Position = 2,Mandatory = $false,
        HelpMessage = 'Some sites may require credentials to access the site, usually dev sites hidden behind a Basic Auth logon page')]
        [ValidateSet('y','Y','yes','Yes','YES')]
        [string]$cred
        )

    #Timestamp Function
    Function Get-Timestamp 
    {
        $n = Get-Date
        #pad values with leading 0 if necessary
        $mo = (($n.Month).ToString()).PadLeft(2,'0')
        $dy = (($n.Day).ToString()).PadLeft(2,'0')
        $yr = ($n.Year).ToString()
        $hr = (($n.hour).ToString()).PadLeft(2,'0')
        $mn = (($n.Minute).ToString()).PadLeft(2,'0')
        $sec = (($n.Second).ToString()).PadLeft(2,'0')
        $result = $mo+$dy+$yr+$hr+$mn+$sec
        return $result
    }
 
    #HTTP Sec, Server, X-Powered and other X-Powered Headers
    $secheaders = @(
        'x-xss-protection', 
        'Strict-Transport-Security', 
        'Content-Security-Policy', 
        'Content-Security-Policy-Report-Only', 
        'X-Frame-Options', 
        'X-Content-Type-Options', 
        'Public-Key-Pins', 
        'Public-Key-Pins-Report-Only'
    )

    $serverheader = @(
        'Apache*', 
        'Apache-Coyote*', 
        'Apache Tomcat*', 
        'ARR*', 
        'BOA*', 
        'cloudflare-nginx', 
        'gse', 
        'IBM_HTTP_Server*', 
        'Iweb*', 
        'JBoss*', 
        'JBPAPP*', 
        'JBossWeb*', 
        'Joomla*', 
        'JSF*', 
        'JSP*'
        'Liferay Portal Enterprise Edition*', 
        'lighttpd*', 
        'LiteSpeed*', 
        'Microsoft*', 
        'nginx*', 
        'nweb*', 
        'OpenCms*', 
        'Omniture DC*', 
        'Oracle*', 
        'Sun-Java-System-Web-Server*', 
        'Tomcat*', 
        'TornadoServer*', 
        'WEBrick*', 
        'WebSphere Application Server*'
    )

    $xpowered = @(
        'php*', 
        'asp*', 
        'mono*', 
        'perl*', 
        'ruby*', 
        'Servlet*', 
        'EasyEngine*'
    )

    $otherxpow = @(
        'X-AspNet-Version', 
        'X-AspNetMVC-Version', 
        'X-OWA-Version'
    )
    
    #Main Script
    #Is a log required?
    if($log)
    {
        $time = Get-Timestamp
        $domain = ([System.Uri]$url).Host -replace '^www\.'
        $logfile = '.\Sec-Headers-Log-'+$domain+'-'+$time+'.txt'
        Start-Transcript -Path $logfile
    }

    #Are Creds required?
    if($cred)
    {
        $user = Read-Host 'Enter Usernme: '
        $securepass = Read-Host 'Enter Password: ' -AsSecureString
        $credentials = New-Object System.Management.automation.PSCredential ($user, $securepass)
    }

    #User agent string is required to support Content-Security-Policy retrieval, natively Invoke-WebRequest does not send a user agent string that supports CSP
    $UserAgent = 'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.101 Safari/537.36'
    
    #Webrequest with creds or not
    if($cred)
    {
    $webrequest = Invoke-WebRequest -Uri $url -MaximumRedirection 0 -ErrorAction Ignore -SessionVariable websession -UserAgent $UserAgent -Credential $credentials
    }
    else
    {
    $webrequest = Invoke-WebRequest -Uri $url -MaximumRedirection 0 -ErrorAction Ignore -SessionVariable websession -UserAgent $UserAgent
    }
     
    $cookies = $websession.Cookies.GetCookies($url) 
    Write-Host -Object "`n"
    Write-Host 'Header Information for' $url
    Write-Host -Object ($webrequest.Headers|Out-String)
    Write-Host -ForegroundColor White -Object "HTTP security Headers`nConsider adding the values in RED to improve the security of the webserver. `n"
    #Determine Security Headers
    foreach ($sechead in $secheaders)
    {
        if($webrequest.Headers.ContainsKey($sechead))
        {
            Write-Host -ForegroundColor Green -Object $sechead, ' Header PRESENT'
        } 
        else
        {
            Write-Host -ForegroundColor Red -Object $sechead, ' Header MISSING'
        }
    }    
    
    Write-Host -Object "`n"

    #Cookies
    Write-Host 'Cookies Set by' $url
    Write-Host -Object "Inspect cookies that don't have the HTTPOnly and Secure flags set.`n"
    foreach ($cookie in $cookies) 
    { 
        Write-Host -Object "$($cookie.name) = $($cookie.value)"
        if ($cookie.HttpOnly -eq 'True') 
        {
            Write-Host -ForegroundColor Green 'HTTPOnly Flag Set' = "$($cookie.HttpOnly)"
        }
        else 
        {
            Write-Host -ForegroundColor Red 'HTTPOnly Flag Set' = "$($cookie.HttpOnly)"
        }
        if ($cookie.Secure -eq 'True') 
        {
            Write-Host -ForegroundColor Green 'Secure Flag Set' = "$($cookie.Secure)"
        }
        else 
        {
            Write-Host -ForegroundColor Red 'Secure Flag Set' = "$($cookie.Secure)"
        }
        Write-Host 'Domain' = "$($cookie.Domain) `n"
    }

    #Determine Other Server Headers
    Write-Host -Object "Other Headers that require attention`nThese headers give away information regarding the type of web server, web framework and versions.`nAttackers can use information this to determine vulnerable versions of software for instance.`n"

    foreach ($head in $serverheader)
    {
        if($webrequest.Headers.Keys -match 'server' -and $webrequest.Headers.Values -like $head)
        {
            Write-Host -ForegroundColor Red 'Server: ' $webrequest.Headers.Server
        }
    }
    #Determine X-Powered-By Header Present
    foreach ($xpower in $xpowered)
    {
        if($webrequest.Headers.Keys -match 'x-powered-by' -and $webrequest.Headers.Values -like $xpower)
        {
            Write-Host -ForegroundColor Red 'X-Powered-By: ' $webrequest.Headers.'x-powered-by'
        }
    }
    #Determine Other X- Headers
    foreach ($otherx in $otherxpow)
    {
        if($webrequest.Headers.Keys -match $otherx)
        {
            Write-Host -ForegroundColor Red $otherx $webrequest.Headers.$otherx
        }
    }

    #Stop logging
    if($log)
    {
        Stop-Transcript
    }
}
