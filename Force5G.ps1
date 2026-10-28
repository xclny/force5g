<#
.SYNOPSIS
    Force5GHz Wizard - pin a Windows Wi-Fi connection to the best 5 GHz access point.

.DESCRIPTION
    Run with no arguments to get the interactive wizard.
    Every wizard action is also available as a switchable -Action for scripting.

    Auto-select ("smart") ranks every 5 GHz BSSID of your network using:
      signal strength                              (main factor)
      + radio generation bonus                     (802.11be / ax / ac)
      - DFS channel penalty (52-144, radar drops)
      - AP load penalty (channel utilisation / connected stations, when the AP reports it)
      - co-channel neighbour penalty
    Use -Strategy signal to rank purely by signal strength instead.

.EXAMPLE
    .\Force5GHz-Wizard.ps1                       # interactive wizard
.EXAMPLE
    .\Force5GHz-Wizard.ps1 -Action auto          # pick best 5 GHz AP and pin, no prompts
.EXAMPLE
    .\Force5GHz-Wizard.ps1 -Action auto -Strategy signal -SSID "MyWifi" -MinSignal 50
.EXAMPLE
    .\Force5GHz-Wizard.ps1 -Action watch -Interval 20
#>
param(
    [ValidateSet('wizard','status','force','auto','watch','release')]
    [string]$Action = 'wizard',
    [string]$SSID,
    [string]$Bssid,
    [string]$Interface,
    [ValidateSet('smart','signal')]
    [string]$Strategy = 'smart',
    [int]$Interval = 15,
    [int]$MinSignal = 12,
    [switch]$NoRollback,
    [switch]$Pause
)

$ErrorActionPreference = 'Stop'

# ---------- elevation (self-elevates instead of just failing) ----------

$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($Identity)
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Administrator rights are required - requesting elevation...' -ForegroundColor Yellow
    $ArgList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    foreach ($Key in $PSBoundParameters.Keys) {
        $Val = $PSBoundParameters[$Key]
        if ($Val -is [switch]) { if ($Val.IsPresent) { $ArgList += "-$Key" } }
        else { $ArgList += "-$Key"; $ArgList += "`"$Val`"" }
    }
    if (-not $PSBoundParameters.ContainsKey('Pause')) { $ArgList += '-Pause' }
    try {
        Start-Process -FilePath (Get-Process -Id $PID).Path -Verb RunAs -ArgumentList $ArgList
        exit 0
    } catch {
        Write-Host 'Elevation was cancelled or failed. Re-run from an Administrator PowerShell.' -ForegroundColor Red
        exit 1
    }
}

if (-not ('WifiPin' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class WifiPin
{
    [StructLayout(LayoutKind.Sequential)]
    public struct NDIS_OBJECT_HEADER { public byte Type; public byte Revision; public ushort Size; }

    [StructLayout(LayoutKind.Sequential)]
    public struct DOT11_BSSID_LIST
    {
        public NDIS_OBJECT_HEADER Header;
        public uint uNumEntries;
        public uint uTotalNumEntries;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        public byte[] BSSIDs;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WLAN_CONNECTION_PARAMETERS
    {
        public int wlanConnectionMode;
        [MarshalAs(UnmanagedType.LPWStr)] public string strProfile;
        public IntPtr pDot11Ssid;
        public IntPtr pDesiredBssidList;
        public int dot11BssType;
        public uint dwFlags;
    }

    [DllImport("wlanapi.dll")]
    static extern uint WlanOpenHandle(uint dwClientVersion, IntPtr pReserved, out uint pdwNegotiatedVersion, out IntPtr phClientHandle);

    [DllImport("wlanapi.dll")]
    static extern uint WlanCloseHandle(IntPtr hClientHandle, IntPtr pReserved);

    [DllImport("wlanapi.dll")]
    static extern uint WlanEnumInterfaces(IntPtr hClientHandle, IntPtr pReserved, out IntPtr ppInterfaceList);

    [DllImport("wlanapi.dll")]
    static extern uint WlanScan(IntPtr hClientHandle, ref Guid pInterfaceGuid, IntPtr pDot11Ssid, IntPtr pIeData, IntPtr pReserved);

    [DllImport("wlanapi.dll")]
    static extern void WlanFreeMemory(IntPtr pMemory);

    [DllImport("wlanapi.dll")]
    static extern uint WlanConnect(IntPtr hClientHandle, ref Guid pInterfaceGuid, ref WLAN_CONNECTION_PARAMETERS pConnectionParameters, IntPtr pReserved);

    // Returns 0 on success, or the WlanScan error code.
    public static uint Scan(string guidStr)
    {
        IntPtr h; uint ver;
        uint r = WlanOpenHandle(2, IntPtr.Zero, out ver, out h);
        if (r != 0) return r;
        try
        {
            Guid g = new Guid(guidStr);
            r = WlanScan(h, ref g, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        }
        finally { WlanCloseHandle(h, IntPtr.Zero); }
        return r;
    }

    public static uint Connect(string guidStr, string profile, byte[] mac)
    {
        if (mac == null || mac.Length != 6) return 0xFFFFFFFE;
        IntPtr h; uint ver;
        uint r = WlanOpenHandle(2, IntPtr.Zero, out ver, out h);
        if (r != 0) return r;
        IntPtr pIfaces = IntPtr.Zero;
        try
        {
            r = WlanEnumInterfaces(h, IntPtr.Zero, out pIfaces);
            if (r != 0) return r;
            int c0 = Marshal.ReadInt32(pIfaces, 0);
            int c1 = Marshal.ReadInt32(pIfaces, 4);
            uint count;
            if (c0 >= 1 && c0 <= 8) count = (uint)c0;
            else if (c1 >= 1 && c1 <= 8) count = (uint)c1;
            else count = 0;
            if (count == 0) return 0xFFFFFFFC;
            Guid target = new Guid(guidStr);
            bool found = false;
            for (uint i = 0; i < count; i++)
            {
                IntPtr p = IntPtr.Add(pIfaces, 8 + (int)i * 532);
                Guid g = (Guid)Marshal.PtrToStructure(p, typeof(Guid));
                if (g == target) { found = true; break; }
            }
            if (!found) return 0xFFFFFFFD;
            DOT11_BSSID_LIST list = new DOT11_BSSID_LIST();
            list.Header.Type = 0x80;   // NDIS_OBJECT_TYPE_DEFAULT
            list.Header.Revision = 1;
            list.Header.Size = (ushort)Marshal.SizeOf(typeof(DOT11_BSSID_LIST));
            list.uNumEntries = 1;
            list.uTotalNumEntries = 1;
            list.BSSIDs = mac;
            IntPtr pList = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(DOT11_BSSID_LIST)));
            try
            {
                Marshal.StructureToPtr(list, pList, false);
                WLAN_CONNECTION_PARAMETERS cp = new WLAN_CONNECTION_PARAMETERS();
                cp.wlanConnectionMode = 0;
                cp.strProfile = profile;
                cp.pDot11Ssid = IntPtr.Zero;
                cp.pDesiredBssidList = pList;
                cp.dot11BssType = 1;
                cp.dwFlags = 0;
                r = WlanConnect(h, ref target, ref cp, IntPtr.Zero);
            }
            finally { Marshal.FreeHGlobal(pList); }
            return r;
        }
        finally
        {
            if (pIfaces != IntPtr.Zero) WlanFreeMemory(pIfaces);
            WlanCloseHandle(h, IntPtr.Zero);
        }
    }
}
'@
}

$ErrorActionPreference = 'SilentlyContinue'

# ---------- helpers ----------

function Get-WifiAdapters {
    @(Get-NetAdapter | Where-Object {
        $_.Status -ne 'Not Present' -and $_.Status -ne 'Disabled' -and
        ($_.InterfaceDescription -match 'Wireless|Wi-?Fi|802\.11|WLAN|Tenda' -or $_.PhysicalMediaType -match '802\.11')
    })
}

function Get-TargetInterface {
    if ($Interface) { return $Interface }
    $Adapter = Get-NetAdapter | Where-Object { $_.InterfaceDescription -match 'Tenda' } | Select-Object -First 1
    if ($Adapter) { return $Adapter.Name }
    $Wifi = @(Get-WifiAdapters) | Select-Object -First 1
    if ($Wifi) { return $Wifi.Name }
    return 'Wi-Fi'
}

function Get-SavedProfiles {
    param([string]$Iface)
    $Names = @()
    foreach ($Line in (netsh wlan show profiles interface="$Iface")) {
        if ($Line -match '^\s*(?:All User|Per-user|Current User) Profile\s*:\s*(.+)$') {
            $Val = $Matches[1].Trim()
            if ($Val -and $Val -ne '<None>') { $Names += $Val }
        }
    }
    return @($Names | Sort-Object -Unique)
}

function New-ApRecord {
    param($R)
    if (-not $R.Band -and $R.Channel) {
        if ($R.Channel -le 14) { $R.Band = '2.4 GHz' } else { $R.Band = '5 GHz' }
    }
    return [pscustomobject]$R
}

# Parses `netsh wlan show networks mode=bssid` output (English Windows).
# A record is closed when the next BSSID/SSID starts, so fields that netsh
# prints after "Channel" (Bss Load: stations / utilisation) are captured too.
function ConvertFrom-NetshBss {
    param([string[]]$Lines)
    $Out = New-Object System.Collections.ArrayList
    $CurSsid = $null
    $Rec = $null
    foreach ($Line in $Lines) {
        if ($Line -match '^\s*SSID\s+\d+\s+:\s*(.*)$') {
            if ($Rec) { [void]$Out.Add((New-ApRecord $Rec)); $Rec = $null }
            $CurSsid = $Matches[1].Trim()
        } elseif ($Line -match '^\s*BSSID\s+\d+\s+:\s*([0-9a-fA-F:]{17})') {
            if ($Rec) { [void]$Out.Add((New-ApRecord $Rec)) }
            $Rec = @{ SSID = $CurSsid; BSSID = $Matches[1].ToUpper(); Band = $null; Channel = 0; Signal = 0; Radio = $null; Stations = $null; Util = $null }
        } elseif ($Rec) {
            if ($Line -match '^\s*Signal\s+:\s*(\d+)') { $Rec.Signal = [int]$Matches[1] }
            elseif ($Line -match '^\s*Radio type\s+:\s*(.+)$') { $Rec.Radio = $Matches[1].Trim() }
            elseif ($Line -match '^\s*Band\s+:\s*(.+)$') { $Rec.Band = $Matches[1].Trim() }
            elseif ($Line -match '^\s*Channel\s+:\s*(\d+)') { $Rec.Channel = [int]$Matches[1] }
            elseif ($Line -match 'Connected Stations\s*:\s*(\d+)') { $Rec.Stations = [int]$Matches[1] }
            elseif ($Line -match 'Channel Utilization\s*:\s*(\d+)\s*\((\d+)\s*%\)') { $Rec.Util = [int]$Matches[2] }
            elseif ($Line -match 'Channel Utilization\s*:\s*(\d+)') { $Rec.Util = [int][math]::Round([int]$Matches[1] * 100 / 255) }
        }
    }
    if ($Rec) { [void]$Out.Add((New-ApRecord $Rec)) }
    return $Out.ToArray()
}

function Get-ApScan {
    param([string]$Iface, [string]$Target, [int]$Tries = 4, [int]$DelayMs = 2500)

    # Ask the driver to actually scan (fixes stale/partial netsh cache).
    $guid = (Get-Connection $Iface).GUID
    if ($guid) {
        $null = [WifiPin]::Scan($guid)
        Start-Sleep -Milliseconds 1500
    }

    $Aps = @()
    for ($t = 1; $t -le $Tries; $t++) {
        if ($t -gt 1) { Start-Sleep -Milliseconds $DelayMs }
        $Aps = @(ConvertFrom-NetshBss (netsh wlan show networks mode=bssid interface="$Iface"))
        if ($Target) {
            if (@($Aps | Where-Object { $_.SSID -eq $Target -and $_.Band -like '5*' }).Count -gt 0) { break }
        } elseif ($Aps.Count -ge 3) { break }
    }
    return ,$Aps
}

function Get-Connection {
    param([string]$Iface)
    $Lines = netsh wlan show interfaces
    $R = @{ State = 'disconnected'; SSID = $null; Band = $null; Channel = 0; Rate = 0; Signal = 0; BSSID = $null; GUID = $null }
    $Active = $false
    foreach ($Line in $Lines) {
        if ($Line -match '^\s*Name\s+:\s*(.+)$') {
            $Active = ($Matches[1].Trim() -eq $Iface)
            continue
        }
        if (-not $Active) { continue }
        if ($Line -match '^\s*State\s+:\s*(.+)$') { $R.State = $Matches[1].Trim() }
        elseif ($Line -match '^\s*GUID\s+:\s*(.+)$') { $R.GUID = $Matches[1].Trim().Trim('{}') }
        elseif ($Line -match '^\s*SSID\s+:\s*(.+)$') { $R.SSID = $Matches[1].Trim() }
        elseif ($Line -match '^\s*AP BSSID\s+:\s*(.+)$') { $R.BSSID = $Matches[1].Trim().ToUpper() }
        elseif ($Line -match '^\s*Band\s+:\s*(.+)$') { $R.Band = $Matches[1].Trim() }
        elseif ($Line -match '^\s*Channel\s+:\s*(\d+)') { $R.Channel = [int]$Matches[1] }
        elseif ($Line -match '^\s*Transmit rate \(Mbps\)\s+:\s*(\d+)') { $R.Rate = [int]$Matches[1] }
        elseif ($Line -match '^\s*Signal\s+:\s*(\d+)') { $R.Signal = [int]$Matches[1] }
    }
    if (-not $R.Band -and $R.Channel) {
        if ($R.Channel -le 14) { $R.Band = '2.4 GHz' } else { $R.Band = '5 GHz' }
    }
    return $R
}

function ConvertTo-Mac {
    param([string]$Bssid)
    $Hex = $Bssid -replace '[:-]', ''
    if ($Hex.Length -ne 12) { return $null }
    $Bytes = New-Object byte[] 6
    for ($i = 0; $i -lt 6; $i++) { $Bytes[$i] = [Convert]::ToByte($Hex.Substring($i * 2, 2), 16) }
    return ,$Bytes
}

function Format-Bssid {
    param([string]$Bssid)
    if (-not $Bssid) { return '' }
    return ($Bssid -replace '[:-]', '').ToUpper()
}

function Invoke-Pin {
    param([string]$Guid, [string]$Target, [string]$Bssid)
    $Mac = ConvertTo-Mac $Bssid
    if (-not $Mac) { Write-Host "[pin] bad BSSID '$Bssid'"; return $false }
    $Code = $null
    $Code = [WifiPin]::Connect($Guid, $Target, $Mac)
    if ($null -eq $Code) { Write-Host '[pin] WifiPin unavailable (Add-Type failed)'; return $false }
    if ($Code -eq 0) { return $true }
    if ($Code -eq 0xFFFFFFFE) { Write-Host '[pin] bad MAC bytes' }
    elseif ($Code -eq 0xFFFFFFFD) { Write-Host '[pin] interface GUID not in WlanEnumInterfaces list' }
    elseif ($Code -eq 0xFFFFFFFC) { Write-Host '[pin] WlanEnumInterfaces returned empty list' }
    else { Write-Host ('[pin] WlanConnect failed: 0x{0:X8}' -f $Code) }
    return $false
}

function Wait-Connected {
    param([string]$Iface, [string]$Target, [int]$Seconds)
    $Deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $Deadline) {
        $C = Get-Connection $Iface
        if ($C.State -eq 'connected' -and ($C.SSID -eq $Target -or -not $Target)) { return $C }
        Start-Sleep -Seconds 2
    }
    return $null
}

function Get-TargetName {
    param([string]$Requested, [string]$Iface)
    if ($Requested) { return $Requested }
    $C = Get-Connection $Iface
    if ($C.SSID) { return $C.SSID }
    $Names = @(Get-SavedProfiles $Iface)
    if ($Names.Count -eq 1) { return $Names[0] }
    if ($Names.Count -gt 1) { return ('__LIST__' + ($Names -join ' | ')) }
    return $null
}

# ---------- best-5GHz selection ----------

function Get-ApScore {
    param($Ap, $All, [string]$Strat)
    $S = [double]$Ap.Signal
    if ($Strat -eq 'signal') { return [math]::Round($S, 1) }

    $Radio = [string]$Ap.Radio
    if ($Radio -match '802\.11be') { $S += 8 }
    elseif ($Radio -match '802\.11ax') { $S += 6 }
    elseif ($Radio -match '802\.11ac') { $S += 3 }

    if ($Ap.Channel -ge 52 -and $Ap.Channel -le 144) { $S -= 6 }                    # DFS: can drop on radar events
    if ($null -ne $Ap.Util) { $S -= $Ap.Util * 0.25 }                               # busy channel
    if ($null -ne $Ap.Stations) { $S -= [math]::Min($Ap.Stations, 20) * 0.4 }       # crowded AP

    $Co = @($All | Where-Object {
        $_.BSSID -ne $Ap.BSSID -and $_.Band -like '5*' -and $_.Channel -eq $Ap.Channel -and $_.Signal -ge 30
    }).Count
    $S -= [math]::Min($Co, 3) * 3                                                   # co-channel contention

    return [math]::Round($S, 1)
}

function Get-Best5g {
    param([string]$Iface, [string]$Target, [int]$Min, [string]$Strat)
    $Aps = Get-ApScan -Iface $Iface -Target $Target
    $Five = @($Aps | Where-Object { $_.SSID -eq $Target -and $_.Band -like '5*' })
    if ($Five.Count -eq 0) { return @{ Result = 'no5g'; Aps = $Aps; Five = @() } }
    foreach ($Ap in $Five) {
        $Ap | Add-Member -NotePropertyName Score -NotePropertyValue (Get-ApScore $Ap $Aps $Strat) -Force
    }
    $Ranked = @($Five | Sort-Object Score -Descending)
    $Good = @($Ranked | Where-Object { $_.Signal -ge $Min })
    if ($Good.Count -eq 0) {
        return @{ Result = 'weak'; Aps = $Aps; Five = $Ranked; Max = ($Ranked | Measure-Object Signal -Maximum).Maximum }
    }
    return @{ Result = 'ok'; Aps = $Aps; Five = $Ranked; Good = $Good; Best = $Good[0] }
}

function Show-Ranked {
    param($Five, [int]$Min, [switch]$Numbered)
    Write-Host ''
    Write-Host ('  {0,-3} {1,-17}  {2,4}  {3,4}  {4,-9} {5,5}  {6,5}' -f '#', 'BSSID', 'Ch', 'Sig', 'Radio', 'Load', 'Score') -ForegroundColor DarkGray
    $i = 1
    foreach ($Ap in $Five) {
        $Load = '-'
        if ($null -ne $Ap.Util) { $Load = "$($Ap.Util)%" }
        $Radio = $Ap.Radio -replace '802\.11', ''
        $Flag = ''
        if ($Ap.Signal -lt $Min) { $Flag = '  (below min)' }
        elseif ($Ap.Channel -ge 52 -and $Ap.Channel -le 144) { $Flag = '  (DFS)' }
        $Color = 'Gray'
        if ($i -eq 1 -and $Ap.Signal -ge $Min) { $Color = 'Green' }
        Write-Host ('  {0,-3} {1,-17}  {2,4}  {3,3}%  {4,-9} {5,5}  {6,5}{7}' -f $i, $Ap.BSSID, $Ap.Channel, $Ap.Signal, $Radio, $Load, $Ap.Score, $Flag) -ForegroundColor $Color
        $i++
    }
}

# ---------- core actions ----------

# -Optimize: even when already on 5 GHz, move to a clearly better 5 GHz AP (used by -Action auto).
function Invoke-Force {
    param([string]$Iface, [string]$Target, [string]$PinBssid, [bool]$Rollback, [int]$Min, [string]$Strat = 'smart', [bool]$Optimize = $false)
    $Margin = 5   # score points a new AP must win by before we leave a working 5 GHz AP
    $Conn = Get-Connection $Iface
    $Norm = Format-Bssid $PinBssid
    $Cur = Format-Bssid $Conn.BSSID
    if ($Conn.State -eq 'connected') {
        if ($Norm -and $Cur -eq $Norm) {
            Write-Host "[ok] already pinned to $PinBssid ch$($Conn.Channel) $($Conn.Signal)%"
            return 'locked'
        }
        if (-not $Norm -and -not $Optimize -and $Conn.Band -like '5*') {
            Write-Host "[ok] already on 5 GHz $($Conn.BSSID) ch$($Conn.Channel) $($Conn.Signal)%"
            return 'locked'
        }
    }
    if (-not $Norm) {
        $Pick = Get-Best5g -Iface $Iface -Target $Target -Min $Min -Strat $Strat
        if ($Pick.Result -eq 'no5g') {
            Write-Host "[scan] 5 GHz of '$Target' not visible on $Iface ($($Pick.Aps.Count) BSSID(s) in scan)"
            return 'no5g'
        }
        if ($Pick.Result -eq 'weak') {
            Write-Host "[scan] 5 GHz visible but weak ($($Pick.Max)% < -MinSignal $Min) - refusing cutover"
            return 'weak'
        }
        $Best = $Pick.Best
        if ($Optimize -and $Conn.State -eq 'connected' -and $Conn.Band -like '5*') {
            if ($Cur -eq (Format-Bssid $Best.BSSID)) {
                Write-Host "[ok] already on the best 5 GHz AP $($Best.BSSID) ch$($Best.Channel) $($Best.Signal)%"
                return 'locked'
            }
            $CurAp = $Pick.Five | Where-Object { (Format-Bssid $_.BSSID) -eq $Cur } | Select-Object -First 1
            if ($CurAp -and ($Best.Score - $CurAp.Score) -lt $Margin) {
                Write-Host "[ok] current 5 GHz AP (score $($CurAp.Score)) is within $Margin of the best ($($Best.Score)) - staying put"
                return 'locked'
            }
        }
        $PinBssid = $Best.BSSID
        $Norm = Format-Bssid $PinBssid
        Write-Host "[scan] best 5 GHz ($Strat): $PinBssid ch$($Best.Channel) $($Best.Signal)% score $($Best.Score)"
    } else {
        Write-Host "[pin] target $PinBssid"
    }
    if (-not $Conn.GUID) { Write-Host '[pin] no interface GUID parsed'; return 'noguid' }
    Write-Host "[pin] WlanConnect -> $PinBssid | profile '$Target'"
    $Pinned = Invoke-Pin -Guid $Conn.GUID -Target $Target -Bssid $PinBssid
    if (-not $Pinned) {
        $Now = Get-Connection $Iface
        if ($Now.State -eq 'connected' -and $Now.SSID -eq $Target) {
            Write-Host '[pin] failed, current connection untouched'
            return 'fail'
        }
        if (-not $Rollback) { Write-Host '[warn] pin failed, -NoRollback set'; return 'fail' }
        Write-Host '[rollback] pin failed - reconnecting normally'
        netsh wlan connect name="$Target" interface="$Iface" | Out-Null
        $Back = Wait-Connected $Iface $Target 20
        if ($Back) { Write-Host "[rollback] auto band: $($Back.Band) ch$($Back.Channel) $($Back.Signal)%" }
        return 'rolledback'
    }
    $Deadline = (Get-Date).AddSeconds(25)
    $Locked = $null
    while ((Get-Date) -lt $Deadline) {
        $C2 = Get-Connection $Iface
        if ($C2.State -eq 'connected' -and (Format-Bssid $C2.BSSID) -eq $Norm) { $Locked = $C2; break }
        Start-Sleep -Seconds 2
    }
    if ($Locked) {
        Write-Host "[ok] pinned: $($Locked.Band) $($Locked.BSSID) ch$($Locked.Channel) $($Locked.Signal)% $($Locked.Rate) Mbps"
        return 'locked'
    }
    if (-not $Rollback) { Write-Host '[warn] association to pinned BSSID failed, -NoRollback set'; return 'fail' }
    Write-Host '[rollback] pinned BSSID unreachable - reconnecting with normal band selection'
    netsh wlan disconnect interface="$Iface" | Out-Null
    Start-Sleep -Seconds 2
    netsh wlan connect name="$Target" interface="$Iface" | Out-Null
    $Back = Wait-Connected $Iface $Target 20
    if ($Back) { Write-Host "[rollback] auto band: $($Back.Band) ch$($Back.Channel) $($Back.Signal)% $($Back.Rate) Mbps" }
    else { Write-Host '[rollback] reconnecting in background' }
    return 'rolledback'
}

function Invoke-Release {
    param([string]$Iface, [string]$Target)
    Write-Host '[release] pins are per-connect - reconnecting with normal band selection'
    netsh wlan disconnect interface="$Iface" | Out-Null
    Start-Sleep -Seconds 2
    netsh wlan connect name="$Target" interface="$Iface" | Out-Null
    $Back = Wait-Connected $Iface $Target 20
    if ($Back) { Write-Host "[release] connected: $($Back.Band) ch$($Back.Channel) $($Back.Signal)% $($Back.BSSID) $($Back.Rate) Mbps" }
    else { Write-Host '[release] reconnect pending' }
}

function Show-Status {
    param([string]$Iface, [string]$Target)
    $C = Get-Connection $Iface
    Write-Host ''
    Write-Host "interface : $Iface"
    Write-Host "state     : $($C.State)"
    Write-Host "ssid      : $($C.SSID)"
    Write-Host "band      : $($C.Band) | ch $($C.Channel) | $($C.Signal)% | $($C.Rate) Mbps | $($C.BSSID)"
    if (-not $Target) { $Target = if ($SSID) { $SSID } else { $C.SSID } }
    $Aps = Get-ApScan -Iface $Iface -Target $Target
    if ($Aps.Count -gt 0) {
        $Aps | Sort-Object SSID, Band, Channel | Format-Table SSID, BSSID, Band, Channel, Signal, Radio -AutoSize | Out-Host
    } else {
        Write-Host 'scan      : nothing visible'
    }
    if ($Target) {
        $Five = @($Aps | Where-Object { $_.SSID -eq $Target -and $_.Band -like '5*' })
        $Two = @($Aps | Where-Object { $_.SSID -eq $Target -and $_.Band -eq '2.4 GHz' })
        Write-Host "'$Target' visible: $($Five.Count) x 5 GHz, $($Two.Count) x 2.4 GHz"
        if ($Five.Count -gt 0) {
            foreach ($Ap in $Five) { $Ap | Add-Member -NotePropertyName Score -NotePropertyValue (Get-ApScore $Ap $Aps $Strategy) -Force }
            Write-Host "5 GHz ranking ($Strategy):" -ForegroundColor Cyan
            Show-Ranked -Five @($Five | Sort-Object Score -Descending) -Min $MinSignal
        }
    }
}

function Invoke-Watch {
    param([string]$Iface, [string]$Target, [int]$Poll)
    if ($Poll -lt 5) { $Poll = 5 }
    Write-Host "watching '$Target' on $Iface | pin to best 5 GHz ($Strategy) >= $MinSignal% | poll ${Poll}s | Ctrl+C stop"
    while ($true) {
        $Stamp = Get-Date -Format 'HH:mm:ss'
        $C = Get-Connection $Iface
        if ($C.State -eq 'connected' -and $C.Band -like '5*') {
            Write-Host "[$Stamp] holding 5 GHz $($C.BSSID) ch$($C.Channel) $($C.Signal)% $($C.Rate) Mbps"
        } else {
            $Pick = Get-Best5g -Iface $Iface -Target $Target -Min $MinSignal -Strat $Strategy
            if ($Pick.Result -eq 'ok') {
                $null = Invoke-Force -Iface $Iface -Target $Target -PinBssid $Pick.Best.BSSID -Rollback $true -Min $MinSignal -Strat $Strategy
            } else {
                $Hint = ''
                if ($C.State -ne 'connected') { $Hint = ' | NOT CONNECTED - use release for auto-band fallback' }
                elseif ($Pick.Five.Count -gt 0) { $Hint = " | 5 GHz weak (max $($Pick.Max)% < $MinSignal%)" }
                Write-Host "[$Stamp] waiting for usable 5 GHz ($($Pick.Five.Count) visible)$Hint"
            }
        }
        Start-Sleep -Seconds $Poll
    }
}

# ---------- wizard ----------

function Show-Menu {
    param([string]$Title, [string[]]$Items, [int]$Default = 1)
    Write-Host ''
    Write-Host "=== $Title ===" -ForegroundColor Cyan
    for ($i = 0; $i -lt $Items.Count; $i++) {
        $n = $i + 1
        $mark = if ($n -eq $Default) { '*' } else { ' ' }
        Write-Host ("  {0}{1}) {2}" -f $mark, $n, $Items[$i])
    }
    while ($true) {
        $raw = Read-Host "Select [default $Default]"
        if ([string]::IsNullOrWhiteSpace($raw)) { return $Default }
        $n = 0
        if ([int]::TryParse($raw, [ref]$n) -and $n -ge 1 -and $n -le $Items.Count) { return $n }
        Write-Host 'Invalid choice.' -ForegroundColor Yellow
    }
}

function Confirm-Yes {
    param([string]$Question, [bool]$Default = $true)
    $Hint = if ($Default) { 'Y/n' } else { 'y/N' }
    $raw = Read-Host "$Question [$Hint]"
    if ([string]::IsNullOrWhiteSpace($raw)) { return $Default }
    return ($raw.Trim() -match '^(y|yes)$')
}

function Select-Adapter {
    $Adapters = @(Get-WifiAdapters)
    if ($Adapters.Count -eq 0) {
        Write-Host 'No wireless adapters found.' -ForegroundColor Red
        return $null
    }
    if ($Interface) {
        $Pref = $Adapters | Where-Object { $_.Name -eq $Interface } | Select-Object -First 1
        if ($Pref) { return $Pref.Name }
    }
    if ($Adapters.Count -eq 1) {
        Write-Host "adapter : $($Adapters[0].Name) ($($Adapters[0].InterfaceDescription))" -ForegroundColor Green
        return $Adapters[0].Name
    }
    $Labels = @($Adapters | ForEach-Object { "$($_.Name)  ($($_.InterfaceDescription))  [$($_.Status)]" })
    $Def = 1
    for ($i = 0; $i -lt $Adapters.Count; $i++) { if ($Adapters[$i].InterfaceDescription -match 'Tenda') { $Def = $i + 1; break } }
    $Pick = Show-Menu -Title 'Wireless adapter' -Items $Labels -Default $Def
    return $Adapters[$Pick - 1].Name
}

function Select-Ssid {
    param([string]$Iface)
    if ($SSID) { return $SSID }
    $Profiles = @(Get-SavedProfiles $Iface)
    if ($Profiles.Count -eq 0) {
        Write-Host 'No saved Wi-Fi profiles on this adapter. Connect to your network once, then re-run.' -ForegroundColor Red
        return $null
    }
    $Current = (Get-Connection $Iface).SSID
    if ($Profiles.Count -eq 1) {
        Write-Host "network : $($Profiles[0])" -ForegroundColor Green
        return $Profiles[0]
    }
    $Def = 1
    if ($Current) { $i = [array]::IndexOf($Profiles, $Current); if ($i -ge 0) { $Def = $i + 1 } }
    $Pick = Show-Menu -Title 'Network (SSID)' -Items $Profiles -Default $Def
    return $Profiles[$Pick - 1]
}

function Show-ForceResult {
    param([string]$Result)
    Write-Host ''
    switch ($Result) {
        'locked'     { Write-Host 'Done - on 5 GHz.' -ForegroundColor Green }
        'rolledback' { Write-Host 'Pin failed - rolled back to automatic band.' -ForegroundColor Yellow }
        'fail'       { Write-Host 'Pin failed.' -ForegroundColor Red }
        'no5g'       { Write-Host 'No 5 GHz AP found.' -ForegroundColor Yellow }
        'weak'       { Write-Host '5 GHz is too weak.' -ForegroundColor Yellow }
        default      { Write-Host "Result: $Result" -ForegroundColor Yellow }
    }
}

function Invoke-WizardPin {
    param([string]$Iface, [string]$Target, [bool]$Choose)
    Write-Host ''
    Write-Host 'Scanning (forcing a real off-channel scan)...' -ForegroundColor Cyan
    $Pick = Get-Best5g -Iface $Iface -Target $Target -Min $MinSignal -Strat $Strategy
    if ($Pick.Result -eq 'no5g') {
        Write-Host "No 5 GHz APs visible for '$Target' after a fresh scan." -ForegroundColor Yellow
        if ($Pick.Aps.Count -gt 0) {
            $Pick.Aps | Sort-Object SSID, Band, Channel | Format-Table SSID, BSSID, Band, Channel, Signal -AutoSize | Out-Host
        }
        return
    }
    Write-Host "5 GHz APs for '$Target' - ranked by '$Strategy':" -ForegroundColor Cyan
    Show-Ranked -Five $Pick.Five -Min $MinSignal
    Write-Host ''
    if ($Pick.Result -eq 'weak') {
        Write-Host "Strongest 5 GHz is $($Pick.Max)%, below the minimum of $MinSignal%. Lower it in Settings or move closer." -ForegroundColor Yellow
        if (-not $Choose) { return }
    }

    if ($Choose) {
        $Sel = Read-Host "Pick an AP [1-$($Pick.Five.Count)] (Enter to cancel)"
        $n = 0
        if (-not [int]::TryParse($Sel, [ref]$n) -or $n -lt 1 -or $n -gt $Pick.Five.Count) {
            Write-Host 'Cancelled.'
            return
        }
        $Chosen = $Pick.Five[$n - 1]
        if ($Chosen.Signal -lt $MinSignal -and -not (Confirm-Yes "That AP is only $($Chosen.Signal)% - connect anyway?" $false)) { return }
    } else {
        $Chosen = $Pick.Best
        Write-Host "Best: $($Chosen.BSSID)  ch$($Chosen.Channel)  $($Chosen.Signal)%  score $($Chosen.Score)" -ForegroundColor Green
        if (-not (Confirm-Yes 'Connect to it?' $true)) { return }
    }
    $Result = Invoke-Force -Iface $Iface -Target $Target -PinBssid $Chosen.BSSID -Rollback (-not $NoRollback) -Min $MinSignal -Strat $Strategy
    Show-ForceResult $Result
}

function Show-Settings {
    while ($true) {
        $Items = @(
            "Selection strategy: $Strategy   (smart = signal + radio + load + DFS; signal = strongest only)",
            "Minimum signal: $MinSignal%   (never pin an AP weaker than this)",
            "Watch poll interval: ${Interval}s",
            'Back'
        )
        $m = Show-Menu -Title 'Settings' -Items $Items -Default 4
        switch ($m) {
            1 { $script:Strategy = if ($Strategy -eq 'smart') { 'signal' } else { 'smart' } }
            2 {
                $raw = Read-Host 'New minimum signal % (1-100)'
                $n = 0
                if ([int]::TryParse($raw, [ref]$n) -and $n -ge 1 -and $n -le 100) { $script:MinSignal = $n } else { Write-Host 'Unchanged.' -ForegroundColor Yellow }
            }
            3 {
                $raw = Read-Host 'New poll interval in seconds (min 5)'
                $n = 0
                if ([int]::TryParse($raw, [ref]$n) -and $n -ge 5) { $script:Interval = $n } else { Write-Host 'Unchanged.' -ForegroundColor Yellow }
            }
            4 { return }
        }
    }
}

function Invoke-Wizard {
    Write-Host ''
    Write-Host '=========================================' -ForegroundColor Cyan
    Write-Host '  Force5GHz Wizard' -ForegroundColor Cyan
    Write-Host '=========================================' -ForegroundColor Cyan

    $Iface = Select-Adapter
    if (-not $Iface) { return 1 }
    $Target = Select-Ssid -Iface $Iface
    if (-not $Target) { return 1 }

    while ($true) {
        $C = Get-Connection $Iface
        Write-Host ''
        Write-Host ("adapter {0} | network '{1}' | strategy {2} | min signal {3}%" -f $Iface, $Target, $Strategy, $MinSignal) -ForegroundColor DarkGray
        if ($C.State -eq 'connected') {
            Write-Host ("now: {0} | {1} | ch {2} | {3}% | {4} Mbps | {5}" -f $C.SSID, $C.Band, $C.Channel, $C.Signal, $C.Rate, $C.BSSID) -ForegroundColor Gray
        } else {
            Write-Host "now: $($C.State)" -ForegroundColor Yellow
        }
        $Items = @(
            'Auto-select the best 5 GHz AP and connect  (recommended)',
            'Choose a specific 5 GHz AP from a list',
            'Watch mode - keep re-pinning to 5 GHz  (Ctrl+C exits)',
            'Release - go back to automatic band selection',
            'Status and full scan',
            'Settings (strategy, minimum signal, watch interval)',
            'Change adapter / network',
            'Quit'
        )
        $m = Show-Menu -Title 'What would you like to do?' -Items $Items -Default 1
        switch ($m) {
            1 { Invoke-WizardPin -Iface $Iface -Target $Target -Choose $false }
            2 { Invoke-WizardPin -Iface $Iface -Target $Target -Choose $true }
            3 { Invoke-Watch -Iface $Iface -Target $Target -Poll $Interval }
            4 { Invoke-Release -Iface $Iface -Target $Target }
            5 { Show-Status -Iface $Iface -Target $Target }
            6 { Show-Settings }
            7 {
                $script:SSID = $null
                $NewIface = Select-Adapter
                if ($NewIface) { $Iface = $NewIface }
                $NewTarget = Select-Ssid -Iface $Iface
                if ($NewTarget) { $Target = $NewTarget }
            }
            8 { return 0 }
        }
    }
}

# ---------- dispatch ----------

function Invoke-Main {
    if ($Action -eq 'wizard') { return (Invoke-Wizard) }

    $Iface = Get-TargetInterface

    if ($Action -eq 'status') {
        $Target = if ($SSID) { $SSID } else { (Get-Connection $Iface).SSID }
        Show-Status -Iface $Iface -Target $Target
        return 0
    }

    $Target = Get-TargetName -Requested $SSID -Iface $Iface
    if ($Target -like '__LIST__*') { Write-Host ('multiple profiles, pass -SSID: ' + $Target.Substring(8)); return 1 }
    if (-not $Target) { Write-Host 'no SSID - pass -SSID "Name"'; return 1 }

    switch ($Action) {
        'release' { Invoke-Release -Iface $Iface -Target $Target; return 0 }
        'watch'   { Invoke-Watch -Iface $Iface -Target $Target -Poll $Interval; return 0 }
        'force' {
            $Result = Invoke-Force -Iface $Iface -Target $Target -PinBssid $Bssid -Rollback (-not $NoRollback) -Min $MinSignal -Strat $Strategy
            if ($Result -eq 'locked') { return 0 } else { return 1 }
        }
        'auto' {
            # Always evaluates the whole scan and picks the best 5 GHz AP, ignoring -Bssid.
            $Result = Invoke-Force -Iface $Iface -Target $Target -PinBssid '' -Rollback (-not $NoRollback) -Min $MinSignal -Strat $Strategy -Optimize $true
            if ($Result -eq 'locked') { return 0 } else { return 1 }
        }
    }
    return 0
}

$ExitCode = 0
$Res = @(Invoke-Main)
if ($Res.Count -gt 0 -and $Res[-1] -is [int]) { $ExitCode = $Res[-1] }
if ($Pause) { Read-Host 'Press Enter to close' | Out-Null }
exit $ExitCode
