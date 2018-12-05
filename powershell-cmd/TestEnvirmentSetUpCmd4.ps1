#Set-ExecutionPolicy Unrestricted -Force

cmd /c D:\SoftWare-master\vs_community.exe --add Microsoft.VisualStudio.Workload.NetWeb -p --wait
$SystemPath=[environment]::GetEnvironmentVariable("Path","Machine")
$SystemPath+=";C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\MSBuild\15.0\Bin;C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\Common7\IDE;"
[environment]::SetEnvironmentvariable("Path", "$SystemPath","Machine")

