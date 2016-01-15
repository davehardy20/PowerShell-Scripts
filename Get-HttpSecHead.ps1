#Requires -version 3
#
Function Get-HttpSecHead
{
    <#
            .Synopsis
            Retrive HTTP Headers from target webserver
            .Description
            This command will get the HTTP headers from the target webserver and test for the presence of variuos security related HTTP headers and also display the cookie information.
            .Parameter url
            The target http or https link
            .Parameter detail
            This is a switch to provide detailed output based up the find Http header findings



            Written by Dave Hardy, davehardy20@gmail.com @davehrdy20
            with consultancy from Mike Woodhead, @ydoow

            Version 0.3

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
        HelpMessage = 'Detailed header output. yes / no')]
        [ValidateSet('yes','Yes','YES','no','No','NO')]
        [string]$detail
    )
        
    #Detailed Missing HTTP Security Header Descriptions
    $xxssprodetail = "Purpose`nThis response header can be used to configure a user-agent's built in reflective XSS protection. Currently, only Microsoft's Internet Explorer, Google Chrome and Safari (WebKit) support this header.

        Valid Settings
        0 - Disables the XSS Protections offered by the user-agent.
        1 - Enables the XSS Protections
        1; mode=block - Enables XSS protections and instructs the user-agent to block the response in the event that script has been inserted from user input, instead of sanitizing.
        1; report=http://site.com/report - A Chrome and WebKit only directive that tells the user-agent to report potential XSS attacks to a single URL. Data will be POST'd to the report URL in JSON format.
        Common Invalid Settings
        0; mode=block; - A common misconfiguration where the 0 value will disable protections even though the mode=block is defined. It should be noted that Chrome has been enhanced to fail closed and treat this as an invalid setting but still keep default XSS protections in place.
    1 mode=block; - All directives must be separated by a ;. Spaces and , are invalid separators. However, IE and Chrome will default to sanitizing the XSS in this case but not enable blocking mode as everything after the 1 is considered invalid.`n"
    $xcontypeopt = "Purpose`nThis header can be set to protect against MIME type confusion attacks in Internet Explorer 9, Chrome and Safari. Firefox is currently debating the implementation. Content sniffing is a method browsers use to attempt to determine the 'real' content type of a response by looking at the content itself, instead of the response header's content-type value. By returning X-Content-Type-Options: nosniff, certain elements will only load external resources if their content-type matches what is expected. As an example, if a stylesheet is being loaded, the MIME type of the resource must match 'text/css'. For script resources in Internet Explorer, the following content types are valid:

        application/ecmascript
        application/javascript
        application/x-javascript
        text/ecmascript
        text/javascript
        text/jscript
        text/x-javascript
        text/vbs
        text/vbscript
        For Chrome, the following are supported MIME types:

        text/javascript
        text/ecmascript
        application/javascript
        application/ecmascript
        application/x-javascript
        text/javascript1.1
        text/javascript1.2
        text/javascript1.3
        text/jscript
        text/livescript`n
        Valid Settings
        nosniff - This is the only valid setting, it must match nosniff.
        Common Invalid Settings
        'nosniff' - Quotes are not allowed.
    : nosniff - Incorrectly adding an additional : is also invalid.`n"
    $stricttrans = "Purpose`nThe Strict Transport Security (STS) header is for configuring user-agents to only communicate to the server over a secure transport. It is primarily used to protect against man-in-the-middle attacks by forcing all further communications to occur over TLS. Internet Explorer does not currently support the STS header. It should be noted that setting this header on a HTTP response has no effect since values could easily be forged by an active attack. To combat this bootstrapping problem, many browsers contain a preloaded list of sites that are configured for STS.

        Valid Settings
        The following values must exist over the secure connection (HTTPS) and are ineffective if accessed over HTTP.

        max-age=31536000 - Tells the user-agent to cache the domain in the STS list for one year.
        max-age=31536000; includeSubDomains - Tells the user-agent to cache the domain in the STS list for one year and include any sub-domains.
        max-age=0 - Tells the user-agent to remove, or not cache the host in the STS cache.
        Common Invalid Settings
        Setting the includeSubDomains directive on https://www.example.com where users can still access the site at http://example.com. If example.com does not redirect to https://example.com and set the STS header, only direct requests to http://www.example.com will be automatically redirected to https://www.example.com by the user-agent.
        max-age=60 - This only sets the domain in the STS cache for 60 seconds. This is not long enough to protect a user who accesses the site, goes to their local coffee shop and attempts to access the site over http first.
        max-age=31536000 includeSubDomains - Directives must be separated by a ;. In this case Chrome will not add the site to the STS cache even though the max-age value is correct.
        max-age=31536000, includeSubDomains - Same as above.
    max-age=0 - While this is technically a valid configuration. Many sites may do this accidentally, thinking a value of 0 means forever.`n"
    $contentsecuritypol = "Purpose`nContent Security Policy is a collection of directives which can be used to restrict how a page loads various resources. Currently, Internet Explorer only supports a subset of CSP and only with the X-Content-Security-Policy header, however the newly released Edge browser supports CSP 1.0. Chrome and Firefox currently support 1.0 of CSP, however version 1.1 of the policy is currently being developed. Configured properly it can help protect a site's resources from various attacks such as XSS and UI redressing related issues. There are 10 possible directives which can each be configured to restrict when and how resources are loaded.

        default-src - This directive sets defaults for script-src, object-src, style-src, img-src, media-src, frame-src, font-src and connect-src. If none of the previous directives exist in the policy the user-agent will enact the rules of the default-src values.
        script-src - Also has two additional settings:
        unsafe-inline - Allows the resource to execute script code. An example would be code that exists in an HTML element's on* event values, or the text content of a script element inside the protected resource.
        unsafe-eval - Allows the resource to execute code dynamically in functions, such as eval, setTimeout, setInterval, new Function etc.
        object-src - Determines where plugins can be loaded and executed from.
        style-src - Determines where CSS or style markup can be loaded from.
        img-src - Determines where images can be loaded from.
        media-src - Determines where video or audio data can be loaded from.
        frame-src - Determines where frames can be embedded from.
        font-src - Determines where fonts can be loaded from.
        connect-src - Restricts which resources can be used in XMLHttpRequest, WebSocket and EventSource.
        sandbox - An optional directive which specifies a sandbox policy for 'safely' embedding content into a sandbox.
        There is also the report-uri directive which can be used to send reports when the policy is violated to a specified URL. This can be helpful for both debugging and being notified of an attack. Additionally, a second header of Content-Security-Policy-Report-Only can be defined to not enforce CSP but to send potential violations to a report URL. It follows the same syntax and rules as the Content-Security-Policy header.

        Valid Settings
        View cspplayground.com compliant examples
        Common Invalid Settings
    View cspplayground.com violation examples`n"
    $xframeoptions = "Purpose`nThis header is for configuring which sites are allowed to frame the loaded resource. Its primary purpose is to protect against UI redressing style attacks. Internet Explorer has supported the ALLOW-FROM directive since IE8 and Firefox from 18. Both Chrome and Safari do not support ALLOW-FROM, however WebKit is currently discussing it.

        Valid Settings
        DENY - Denies any resource (local or remote) from attempting to frame the resource that also supplied the X-Frame-Options header.
        SAMEORIGIN - Allows only resources which are apart of the Same Origin Policy to frame the protected resource.
        ALLOW-FROM http://www.example.com - Allows a single serialized-origin (must have scheme) to frame the protected resource. This is only valid in Internet Explorer and Firefox. The default of other browsers is to allow any origin (as if X-Frame-Options was not set).
        Common Invalid Settings
        ALLOW FROM http://example.com - The ALLOW-FROM directive must use the hyphen character, not a space between allow and from.
    ALLOW-FROM example.com - The ALLOW-FROM directive must use an URI with a valid scheme (http or https).`n"
    $pubkeypin = "Purpose`nThe Public Key Pinning Extension for HTTP (HPKP) is a security feature that tells a web client to associate a specific cryptographic public key with a certain web server to prevent MITM attacks with forged certificates.

        To ensure the authenticity of a server's public key used in TLS sessions, this public key is wrapped into a X.509 certificate which is usually signed by a certificate authority (CA). Web clients such as browsers trust a lot of these CAs, which can all create certificates for arbitrary domain names. If an attacker is able to compromise a single CA, they can perform MITM attacks on various TLS connections. HPKP can circumvent this threat for the HTTPS protocol by telling the client which public key belongs to a certain web server.

        HPKP is a Trust on First Use (TOFU) technique. The first time a web server tells a client via a special HTTP header which public keys belong to it, the client stores this information for a given period of time. When the client visits the server again, it expects a certificate containing a public key whose fingerprint is already known via HPKP. If the server delivers an unknown public key, the client should present a warning to the user.

    Firefox (and Chrome) disable Pin Validation for Pinned Hosts whose validated certificate chain terminates at a user-defined trust anchor (rather than a built-in trust anchor).`n"
    $webrequest = Invoke-WebRequest -Uri $url -SessionVariable websession 
    $cookies = $websession.Cookies.GetCookies($url) 
    Write-Host -Object "`n"
    Write-Host 'Header Information for' $url
    Write-Host -Object ($webrequest.Headers|Out-String)

    Write-Host -ForegroundColor White -Object "HTTP security Headers`nConsider adding the values in RED to improve the security of the webserver. `n"
    #X-XSS-Protection Header
    if($webrequest.Headers.ContainsKey('x-xss-protection')) 
    {
        Write-Host -ForegroundColor Green -Object 'X-XSS-Protection Header PRESENT'
    }
    elseif($detail -eq 'yes')
    {
        Write-Host -ForegroundColor Red -Object "X-Xss-Procetion Header MISSING - Detailed Description`n"
        Write-Host -ForegroundColor Gray -Object $xxssprodetail
    } 
    else
    {
        Write-Host -ForegroundColor Red -Object 'X-XSS-Protection Header MISSING'
    }
    #Strict-Transport-Security Header
    if($webrequest.Headers.ContainsKey('Strict-Transport-Security')) 
    {
        Write-Host -ForegroundColor Green -Object 'Strict-Transport-Security Header PRESENT'
    }
    elseif($detail -eq 'yes') 
    {
        Write-Host -ForegroundColor Red -Object "Strict-Transport-Security Header MISSING - Detailed Descrition`n"
        Write-Host -ForegroundColor Gray -Object $stricttrans
    }
    else
    {
        Write-Host -ForegroundColor Red -Object 'Strict-Transport-Security Header MISSING'
    }
    #Content-Security-Policy Header
    if($webrequest.Headers.ContainsKey('Content-Security-Policy')) 
    {
        Write-Host -ForegroundColor Green -Object 'Content-Security-Policy Header PRESENT'
    }
    elseif($detail -eq 'yes')
    {
        Write-Host -ForegroundColor Red -Object "Content-Security-Header MISSING - Detailed Description`n"
        Write-Host -ForegroundColor Gray -Object $contentsecuritypol
    }
    else 
    {
        Write-Host -ForegroundColor Red -Object 'Content-Security-Policy Header MISSING'
    }
    #X-Frame-Options Header
    if($webrequest.Headers.ContainsKey('X-Frame-Options')) 
    {
        Write-Host -ForegroundColor Green  -Object 'X-Frame-Options Header PRESENT'
    }
    elseif($detail -eq 'yes')
    {
        Write-Host -ForegroundColor Red -Object "X-Frame-Options Header MISSING - Detailed Description`n"
        Write-Host -ForegroundColor Gray -Object $xframeoptions
    }
    else 
    {
        Write-Host -ForegroundColor Red -Object 'X-Frame-Options Header MISSING'
    }
    #X-Content-Type-Options Header
    if($webrequest.Headers.ContainsKey('X-Content-Type-Options')) 
    {
        Write-Host -ForegroundColor Green -Object 'X-Content-Type-Options Header PRESENT'
    }
    elseif($detail -eq 'yes')
    {
        Write-Host -ForegroundColor Red -Object "x-Content-Type-Options Header MISSING - Detailed Description`n"
        Write-Host -ForegroundColor Gray -Object $xcontypeopt
    }
    else
    {
        Write-Host -ForegroundColor Red -Object 'X-Content-Type-Options Header MISSING'
    }
    #Public-Key-Pins Header
    if($webrequest.Headers.ContainsKey('Public-Key-Pins')) 
    {
        Write-Host -ForegroundColor Green -Object 'Public-Key-Pins Header PRESENT'
    }
    elseif($detail -eq 'yes')
    {
        Write-Host -ForegroundColor Red -Object "Public-Key-Pins Header MISSING - Detailed Description`n" 
        Write-Host -ForegroundColor Gray -Object $pubkeypin
    }
    else 
    {
        Write-Host -ForegroundColor Red -Object 'Public-Key-Pins Header MISSING'
    }
    Write-Host -Object "`n"


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

    #Determine Server Header Present
    Write-Host -Object "Other Headers that require attention`nThese headers give away information regarding the type of web server, web framework and versions.`nAttackers can use information this to determine vulnerable versions of software for instance.`n"
    if($webrequest.Headers.Keys -match 'server' -and $webrequest.Headers.Values -like 'apache*') 
    {
        Write-Host -ForegroundColor Red 'Server: ' $webrequest.Headers.Server
    }
    if($webrequest.Headers.Keys -match 'server' -and $webrequest.Headers.Values -like 'nginx*') 
    {
        Write-Host -ForegroundColor Red 'Server: ' $webrequest.Headers.Server
    }
    if($webrequest.Headers.Keys -match 'server' -and $webrequest.Headers.Values -like 'microsoft*') 
    {
        Write-Host -ForegroundColor Red 'Server: ' $webrequest.Headers.Server
    }
    #Determine X-Powered-By Header Present
    if($webrequest.Headers.Keys -match 'x-powered-by' -and $webrequest.Headers.Values -like 'php*') 
    {
        Write-Host -ForegroundColor Red 'X-Powered-By: ' $webrequest.Headers.'x-powered-by'
    }
    if($webrequest.Headers.Keys -match 'x-powered-by' -and $webrequest.Headers.Values -like 'asp.net*') 
    {
        Write-Host -ForegroundColor Red 'X-Powered-By: ' $webrequest.Headers.'x-powered-by'
    }
    if($webrequest.Headers.Keys -match 'x-powered-by' -and $webrequest.Headers.Values -like 'mono*') 
    {
        Write-Host -ForegroundColor Red 'X-Powered-By: ' $webrequest.Headers.'x-powered-by'
    }
    if($webrequest.Headers.Keys -match 'x-powered-by' -and $webrequest.Headers.Values -like 'servlet*') 
    {
        Write-Host -ForegroundColor Red 'X-Powered-By: ' $webrequest.Headers.'x-powered-by'
    }

    #Determine Other X- Headers
    if($webrequest.Headers.Keys -match 'x-aspnet-version') 
    {
        Write-Host -ForegroundColor Red 'X-AspNet-Version: ' $webrequest.Headers.'x-aspnet-version'
    }
    if($webrequest.Headers.Keys -match 'x-aspnetmvc-version') 
    {
        Write-Host -ForegroundColor Red 'X-AspNetMvc-Version: ' $webrequest.Headers.'x-aspnetmvc-version'
    }
    if($webrequest.Headers.Keys -match 'x-owa-version') 
    {
        Write-Host -ForegroundColor Red 'X-OWA-Version: ' $webrequest.Headers.'x-owa-version'
    }
}
