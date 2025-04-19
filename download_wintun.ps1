# 下载wintun.dll文件
$url = "https://www.wintun.net/builds/wintun-0.14.1.zip"
$output = "wintun.zip"
$wintunDir = "wintun"

Write-Host "正在下载wintun.dll文件..."
Invoke-WebRequest -Uri $url -OutFile $output

Write-Host "正在解压文件..."
Expand-Archive -Path $output -DestinationPath $wintunDir -Force

# 根据系统架构选择正确的wintun.dll文件
$arch = [System.Environment]::GetEnvironmentVariable("PROCESSOR_ARCHITECTURE")
if ($arch -eq "AMD64") {
    Write-Host "检测到64位系统，使用amd64版本的wintun.dll"
    Copy-Item -Path "$wintunDir\wintun\bin\amd64\wintun.dll" -Destination "wintun.dll" -Force
} elseif ($arch -eq "x86") {
    Write-Host "检测到32位系统，使用x86版本的wintun.dll"
    Copy-Item -Path "$wintunDir\wintun\bin\x86\wintun.dll" -Destination "wintun.dll" -Force
} elseif ($arch -eq "ARM64") {
    Write-Host "检测到ARM64系统，使用arm64版本的wintun.dll"
    Copy-Item -Path "$wintunDir\wintun\bin\arm64\wintun.dll" -Destination "wintun.dll" -Force
} else {
    Write-Host "无法检测系统架构，默认使用amd64版本的wintun.dll"
    Copy-Item -Path "$wintunDir\wintun\bin\amd64\wintun.dll" -Destination "wintun.dll" -Force
}

# 清理临时文件
Remove-Item -Path $output -Force
Remove-Item -Path $wintunDir -Recurse -Force

Write-Host "wintun.dll文件已下载并放置在当前目录中"
