 $test=Get-Process -Name "java" -ErrorAction "SilentlyContinue"
If (!$?)
{
"error$($error[0])";
read-host

}
$env:Path
read-host