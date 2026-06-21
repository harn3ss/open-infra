# open-infra Windows golden-image post-install.
# Runs once (FirstLogonCommands) after an unattended Server 2022 install:
#   - installs the virtio guest tools + qemu-guest-agent (from the virtio ISO),
#   - installs + enables cloudbase-init (sets the per-VM Administrator password
#     and other cloud-init from the VM's NoCloud userdata on every boot),
#   - enables RDP + the firewall rule,
#   - generalizes the image with sysprep and shuts down -> the disk is the golden
#     image the Composition clones for each `os: windows` VM.
$ErrorActionPreference = 'Stop'
Write-Host 'open-infra: post-install starting'

# --- Locate the virtio ISO (it carries the guest tools + qemu-ga installers) ---
$virtio = (Get-Volume | Where-Object { $_.DriveType -eq 'CD-ROM' } |
  ForEach-Object { $_.DriveLetter } |
  Where-Object { $_ -and (Test-Path ("{0}:\virtio-win-guest-tools.exe" -f $_)) } |
  Select-Object -First 1)

if ($virtio) {
  Write-Host "open-infra: installing virtio guest tools from ${virtio}:"
  Start-Process -Wait -FilePath ("{0}:\virtio-win-guest-tools.exe" -f $virtio) -ArgumentList '/install','/quiet','/norestart'
  $qemuGa = "{0}:\guest-agent\qemu-ga-x86_64.msi" -f $virtio
  if (Test-Path $qemuGa) {
    Start-Process -Wait -FilePath msiexec.exe -ArgumentList '/i', $qemuGa, '/quiet', '/norestart'
  }
} else {
  Write-Warning 'open-infra: virtio ISO not found — guest tools/qemu-ga skipped'
}

# --- Enable Remote Desktop (cloudbase-init re-asserts this per VM too) ---
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0
Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'
Set-Service -Name TermService -StartupType Automatic

# --- Install cloudbase-init (the Windows cloud-init) ---
$cbUrl = 'https://github.com/cloudbase/cloudbase-init/releases/latest/download/CloudbaseInitSetup_x64.msi'
$cbMsi = "$env:TEMP\cloudbase-init.msi"
Write-Host 'open-infra: downloading cloudbase-init'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $cbUrl -OutFile $cbMsi
# Silent install; do NOT run sysprep via the MSI (we control sysprep below).
Start-Process -Wait -FilePath msiexec.exe -ArgumentList '/i', $cbMsi, '/qn', 'RUN_SERVICE_AS_LOCAL_SYSTEM=1', 'LoggingLevel=verbose'

# Point cloudbase-init at the NoCloud (ConfigDrive) datasource KubeVirt presents,
# and allow the password/RDP plugins. Minimal conf; tune as needed.
$cbDir = 'C:\Program Files\Cloudbase Solutions\Cloudbase-Init\conf'
if (Test-Path $cbDir) {
@'
[DEFAULT]
username=Administrator
groups=Administrators
inject_user_password=true
config_drive_raw_hhd=true
config_drive_cdrom=true
config_drive_vfat=true
bsdtar_path=C:\Program Files\Cloudbase Solutions\Cloudbase-Init\bin\bsdtar.exe
mtools_path=C:\Program Files\Cloudbase Solutions\Cloudbase-Init\bin\
metadata_services=cloudbaseinit.metadata.services.nocloudservice.NoCloudConfigDriveService
plugins=cloudbaseinit.plugins.common.mtu.MTUPlugin,cloudbaseinit.plugins.windows.extendvolumes.ExtendVolumesPlugin,cloudbaseinit.plugins.common.userdata.UserDataPlugin,cloudbaseinit.plugins.common.setuserpassword.SetUserPasswordPlugin
allow_reboot=false
stop_service_on_exit=false
'@ | Set-Content -Path (Join-Path $cbDir 'cloudbase-init.conf') -Encoding ASCII
}

# --- Generalize + shut down. The resulting disk is the golden image. ---
Write-Host 'open-infra: sysprep generalize + shutdown'
& "$env:WINDIR\System32\Sysprep\Sysprep.exe" /generalize /oobe /shutdown /quiet
