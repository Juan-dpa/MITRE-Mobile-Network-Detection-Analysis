[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Check', 'NetworkUp', 'NetworkDown', 'NetworkStatus', 'OpenLogWindows', 'CloseLogWindows')]
    [string]$Action,

    [ValidatePattern('^[a-z0-9][a-z0-9-]{0,23}$')]
    [string]$LabId,

    [ValidatePattern('^\d{1,3}(\.\d{1,3}){3}$')]
    [string]$WslAddress,

    [string]$DestinationCsv,
    [string]$StateFile,
    [string]$EmulatorPath,
    [string]$LogSpec,
    [string]$ProcessCsv,
    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$WslDistribution = 'kali-linux',
    [string]$ResultFile
)

$ErrorActionPreference = 'Stop'
$Utf8NoBom = [Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = $Utf8NoBom
$OutputEncoding = $Utf8NoBom
$FirewallGroup = 'TFG Labnet Android'
$OriginalParameters = @{} + $PSBoundParameters
$script:ResultMessage = $null

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Quote-Argument([string]$Value) {
    if ($Value -notmatch '[\s"]') {
        return $Value
    }
    return '"' + $Value.Replace('"', '\"') + '"'
}

function Invoke-ElevatedSelf {
    $resultFile = Join-Path ([IO.Path]::GetTempPath()) `
        ("TFG-Labnet-{0}-{1}.json" -f $LabId, [guid]::NewGuid().ToString('N'))
    $arguments = [System.Collections.Generic.List[string]]::new()
    $arguments.Add('-NoLogo')
    $arguments.Add('-NoProfile')
    $arguments.Add('-ExecutionPolicy')
    $arguments.Add('Bypass')
    $arguments.Add('-File')
    $arguments.Add((Quote-Argument $PSCommandPath))
    foreach ($entry in $script:OriginalParameters.GetEnumerator()) {
        if ($entry.Key -in @('Verbose', 'ResultFile')) {
            continue
        }
        $arguments.Add('-' + $entry.Key)
        $arguments.Add((Quote-Argument ([string]$entry.Value)))
    }
    $arguments.Add('-ResultFile')
    $arguments.Add((Quote-Argument $resultFile))
    try {
        $process = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru `
            -ArgumentList ($arguments -join ' ')
        $result = $null
        if (Test-Path -LiteralPath $resultFile -PathType Leaf) {
            $result = Get-Content -LiteralPath $resultFile -Raw -Encoding utf8 | ConvertFrom-Json
        }
        if ($process.ExitCode -ne 0 -or ($result -and -not $result.Success)) {
            if ($result) {
                $suffix = if ($result.ErrorId) { " [$($result.ErrorId)]" } else { '' }
                throw "La operación elevada $Action falló: $($result.Message)$suffix"
            }
            throw "La operación elevada $Action terminó con código $($process.ExitCode) sin diagnóstico"
        }
        if ($result -and $result.Message) {
            Write-Host "[windows] $($result.Message)"
        }
        else {
            Write-Host "[windows] operación elevada $Action completada"
        }
    }
    finally {
        Remove-Item -LiteralPath $resultFile -Force -ErrorAction SilentlyContinue
    }
    exit 0
}

function ConvertTo-IPv4Integer([string]$Address) {
    $parsed = [Net.IPAddress]::Parse($Address)
    $bytes = $parsed.GetAddressBytes()
    if ($bytes.Length -ne 4) {
        throw "No es una dirección IPv4: $Address"
    }
    return ([uint64]$bytes[0] -shl 24) -bor
        ([uint64]$bytes[1] -shl 16) -bor
        ([uint64]$bytes[2] -shl 8) -bor
        [uint64]$bytes[3]
}

function ConvertFrom-IPv4Integer([uint64]$Value) {
    return '{0}.{1}.{2}.{3}' -f `
        (($Value -shr 24) -band 255),
        (($Value -shr 16) -band 255),
        (($Value -shr 8) -band 255),
        ($Value -band 255)
}

function Convert-IPv4RangeToCidr([uint64]$Start, [uint64]$End) {
    $prefixes = [System.Collections.Generic.List[string]]::new()
    if ($Start -gt $End) {
        return $prefixes.ToArray()
    }
    [uint64]$cursor = $Start
    while ($cursor -le $End) {
        [uint64]$blockSize = 1
        [int]$prefixLength = 32
        for ([int]$candidate = 0; $candidate -le 32; $candidate++) {
            [uint64]$candidateSize = [uint64]1 -shl (32 - $candidate)
            if (($cursor % $candidateSize) -eq 0 -and
                ($candidateSize - 1) -le ($End - $cursor)) {
                $blockSize = $candidateSize
                $prefixLength = $candidate
                break
            }
        }
        if ($prefixLength -eq 32) {
            # El proveedor CIM documenta las direcciones individuales como un
            # formato distinto y no acepta /32 de manera consistente.
            $prefixes.Add((ConvertFrom-IPv4Integer $cursor))
        }
        elseif ($prefixLength -eq 31) {
            # /31 es válido según RFC 3021, pero MSFT_NetFirewallRule puede
            # rechazarlo como prefijo. Dos direcciones individuales expresan
            # exactamente el mismo conjunto sin depender de esa limitación.
            $prefixes.Add((ConvertFrom-IPv4Integer $cursor))
            $prefixes.Add((ConvertFrom-IPv4Integer ($cursor + 1)))
        }
        else {
            $prefixes.Add("$(ConvertFrom-IPv4Integer $cursor)/$prefixLength")
        }
        $cursor += $blockSize
    }
    return $prefixes.ToArray()
}

function Get-IPv4BlockPrefixes([string[]]$AllowedAddresses) {
    # Se bloquea el espacio IPv4 unicast que puede abandonar el emulador, con
    # huecos /32 para los destinos del laboratorio. 0/8, loopback y el espacio
    # multicast/reservado no son rutas de Internet y quedan fuera para evitar
    # prefijos especiales que Windows Defender Firewall rechaza.
    $allowed = @($AllowedAddresses |
        ForEach-Object { ConvertTo-IPv4Integer $_ } |
        Sort-Object -Unique)
    $universes = @(
        [pscustomobject]@{
            Start = ConvertTo-IPv4Integer '1.0.0.0'
            End = ConvertTo-IPv4Integer '126.255.255.255'
        },
        [pscustomobject]@{
            Start = ConvertTo-IPv4Integer '128.0.0.0'
            End = ConvertTo-IPv4Integer '223.255.255.255'
        }
    )
    foreach ($value in $allowed) {
        $covered = $false
        foreach ($universe in $universes) {
            if ($value -ge $universe.Start -and $value -le $universe.End) {
                $covered = $true
                break
            }
        }
        if (-not $covered) {
            throw "El destino permitido no es una dirección IPv4 unicast enrutable: $(ConvertFrom-IPv4Integer $value)"
        }
    }

    $prefixes = [System.Collections.Generic.List[string]]::new()
    foreach ($universe in $universes) {
        [uint64]$cursor = $universe.Start
        foreach ($value in $allowed) {
            [uint64]$current = $value
            if ($current -lt $universe.Start -or $current -gt $universe.End) {
                continue
            }
            if ($cursor -lt $current) {
                foreach ($prefix in @(Convert-IPv4RangeToCidr $cursor ($current - 1))) {
                    $prefixes.Add($prefix)
                }
            }
            $cursor = $current + 1
        }
        if ($cursor -le $universe.End) {
            foreach ($prefix in @(Convert-IPv4RangeToCidr $cursor $universe.End)) {
                $prefixes.Add($prefix)
            }
        }
    }
    return $prefixes.ToArray()
}

function Get-DefaultEmulatorPath {
    if ($EmulatorPath) {
        return $EmulatorPath
    }
    if (-not $env:LOCALAPPDATA) {
        throw 'LOCALAPPDATA no está definido y no se indicó EmulatorPath.'
    }
    return Join-Path $env:LOCALAPPDATA 'Android\Sdk\emulator\emulator.exe'
}

function Get-EmulatorPrograms {
    $launcher = Get-DefaultEmulatorPath
    $emulatorDirectory = Split-Path -Parent $launcher
    $qemu = Join-Path $emulatorDirectory 'qemu\windows-x86_64\qemu-system-x86_64.exe'
    foreach ($path in @($launcher, $qemu)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "No se encuentra un ejecutable del emulador: $path"
        }
    }
    return @($launcher, $qemu)
}

function Get-Destinations {
    if (-not $DestinationCsv) {
        throw 'DestinationCsv no puede estar vacío.'
    }
    $destinations = @($DestinationCsv.Split(',') | Where-Object { $_ })
    foreach ($destination in $destinations) {
        $parsed = [Net.IPAddress]::Parse($destination)
        if ($parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
            throw "Solo se admiten rutas IPv4: $destination"
        }
    }
    return @($destinations | Sort-Object -Unique)
}

function Get-RouteInterfaceIndex([string]$RemoteAddress) {
    $selected = Find-NetRoute -RemoteIPAddress $RemoteAddress | Select-Object -First 1
    if (-not $selected -or -not $selected.InterfaceIndex) {
        throw "Windows no encontró una interfaz capaz de alcanzar WSL en $RemoteAddress."
    }
    return [int]$selected.InterfaceIndex
}

function New-LabFirewallRules(
    [string]$Identifier,
    [string[]]$Destinations,
    [string[]]$Programs
) {
    $prefixes = Get-IPv4BlockPrefixes $Destinations
    $names = [System.Collections.Generic.List[string]]::new()
    $index = 0
    try {
        foreach ($program in $Programs) {
            $baseName = "TFGLabnet-$Identifier-emulator-$index"
            $plannedName = "$baseName-ipv4"
            if (Get-NetFirewallRule -Name $plannedName -ErrorAction SilentlyContinue) {
                throw "Ya existe una regla sin estado del laboratorio: $plannedName"
            }
            $names.Add("$baseName-ipv4")
            New-NetFirewallRule -Name "$baseName-ipv4" -DisplayName "${Identifier}: aislamiento IPv4 del emulador $index" `
                -Group $FirewallGroup -Direction Outbound -Action Block -Enabled True -Profile Any `
                -Program $program -RemoteAddress $prefixes | Out-Null
            $index++
        }
    }
    catch {
        foreach ($name in $names) {
            Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue |
                Remove-NetFirewallRule -Confirm:$false
        }
        throw
    }
    return $names.ToArray()
}

function Remove-LabState([pscustomobject]$State) {
    foreach ($ruleName in @($State.FirewallRules)) {
        Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue |
            Remove-NetFirewallRule -Confirm:$false
    }
    foreach ($destination in @($State.CreatedRoutes)) {
        Get-NetRoute -DestinationPrefix "$destination/32" -InterfaceIndex $State.InterfaceIndex `
            -ErrorAction SilentlyContinue |
            Where-Object { $_.NextHop -eq $State.WslAddress } |
            Remove-NetRoute -Confirm:$false
    }
}

function Invoke-NetworkUp {
    if (-not (Test-IsAdministrator)) {
        Invoke-ElevatedSelf
    }
    if (-not $LabId -or -not $WslAddress -or -not $StateFile) {
        throw 'NetworkUp requiere LabId, WslAddress y StateFile.'
    }
    if (Test-Path -LiteralPath $StateFile) {
        throw "Ya existe estado de red de Windows para ${LabId}: $StateFile"
    }
    $destinations = Get-Destinations
    $programs = Get-EmulatorPrograms
    $interfaceIndex = Get-RouteInterfaceIndex $WslAddress
    $createdRoutes = [System.Collections.Generic.List[string]]::new()
    $firewallRules = @()
    try {
        foreach ($destination in $destinations) {
            $existing = @(Get-NetRoute -DestinationPrefix "$destination/32" -ErrorAction SilentlyContinue)
            if ($existing.Count -gt 0) {
                throw "Ya existe una ruta /32 para $destination; no se sustituirá una ruta ajena."
            }
            New-NetRoute -DestinationPrefix "$destination/32" -InterfaceIndex $interfaceIndex `
                -NextHop $WslAddress -PolicyStore ActiveStore | Out-Null
            $createdRoutes.Add($destination)
        }
        $firewallRules = New-LabFirewallRules $LabId $destinations $programs
        $stateDirectory = Split-Path -Parent $StateFile
        New-Item -ItemType Directory -Path $stateDirectory -Force | Out-Null
        [pscustomobject]@{
            LabId = $LabId
            WslAddress = $WslAddress
            InterfaceIndex = $interfaceIndex
            CreatedRoutes = $createdRoutes.ToArray()
            FirewallRules = @($firewallRules)
            EmulatorPrograms = @($programs)
            CreatedAt = (Get-Date).ToString('o')
        } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $StateFile -Encoding utf8
        $script:ResultMessage = "$($createdRoutes.Count) rutas y $($firewallRules.Count) reglas de aislamiento creadas para $LabId"
        Write-Host "[windows] $($createdRoutes.Count) rutas y $($firewallRules.Count) reglas de aislamiento creadas para $LabId"
    }
    catch {
        $partial = [pscustomobject]@{
            WslAddress = $WslAddress
            InterfaceIndex = $interfaceIndex
            CreatedRoutes = $createdRoutes.ToArray()
            FirewallRules = @($firewallRules)
        }
        Remove-LabState $partial
        throw
    }
}

function Invoke-Check {
    if (-not $LabId -or -not $WslAddress) {
        throw 'Check requiere LabId y WslAddress.'
    }
    $destinations = Get-Destinations
    $programs = Get-EmulatorPrograms
    $interfaceIndex = Get-RouteInterfaceIndex $WslAddress
    foreach ($command in 'Find-NetRoute', 'New-NetRoute', 'New-NetFirewallRule') {
        if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
            throw "No se encuentra el cmdlet requerido: $command"
        }
    }
    $null = Get-IPv4BlockPrefixes $destinations
    Write-Host "[windows] preflight correcto para $LabId; interfaz $interfaceIndex; $($destinations.Count) destinos"
    foreach ($program in $programs) {
        Write-Host "[windows] ejecutable aislado: $program"
    }
}

function Invoke-NetworkDown {
    if (-not (Test-IsAdministrator)) {
        Invoke-ElevatedSelf
    }
    if (-not $StateFile) {
        throw 'NetworkDown requiere StateFile.'
    }
    if (-not (Test-Path -LiteralPath $StateFile)) {
        Write-Host "[windows] no existe estado que retirar: $StateFile"
        return
    }
    $state = Get-Content -LiteralPath $StateFile -Raw -Encoding utf8 | ConvertFrom-Json
    if ($LabId -and $state.LabId -ne $LabId) {
        throw "El estado pertenece a $($state.LabId), no a $LabId."
    }
    Remove-LabState $state
    Remove-Item -LiteralPath $StateFile -Force
    $script:ResultMessage = "rutas y aislamiento retirados para $($state.LabId)"
    Write-Host "[windows] rutas y aislamiento retirados para $($state.LabId)"
}

function Invoke-NetworkStatus {
    if (-not $StateFile -or -not (Test-Path -LiteralPath $StateFile)) {
        Write-Host '[windows] red Android inactiva'
        return
    }
    Get-Content -LiteralPath $StateFile -Raw -Encoding utf8
}

function Invoke-OpenLogWindows {
    if (-not $LabId -or -not $LogSpec) {
        throw 'OpenLogWindows requiere LabId y LogSpec.'
    }
    $started = [System.Collections.Generic.List[int]]::new()
    $tokens = [System.Collections.Generic.List[string]]::new()
    $wsl = (Get-Command 'wsl.exe' -ErrorAction Stop).Source
    try {
        foreach ($entry in ($LogSpec -split ',')) {
            if (-not $entry) {
                continue
            }
            $parts = $entry.Split('|', 2)
            if ($parts.Count -ne 2 -or $parts[0] -notmatch '^[a-z][a-z0-9_-]{0,39}$') {
                throw "Entrada de log no válida: $entry"
            }
            $name = $parts[0]
            $logPath = $parts[1]
            if ($logPath -notmatch '^/[A-Za-z0-9._/+:-]+$') {
                throw "Ruta WSL de log no válida: $logPath"
            }
            $process = Start-Process -FilePath $wsl -WindowStyle Normal -PassThru `
                -ArgumentList @(
                    '-d', $WslDistribution, '--',
                    'tail', '-n', '20', '-F', '--', $logPath
                )
            $started.Add($process.Id)
            $startedAt = $process.StartTime.ToUniversalTime().ToFileTimeUtc()
            $tokens.Add("$($process.Id)@$startedAt")
        }
    }
    catch {
        foreach ($processId in $started) {
            Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
        }
        throw
    }
    if ($started.Count -eq 0) {
        throw 'No se abrió ninguna terminal de log.'
    }
    Write-Host "[windows] $($started.Count) terminal(es) WSL de entidades abiertas"
    Write-Output ("TFG_LOG_PIDS=" + ($tokens -join ','))
}

function Get-DescendantProcessIds([int]$ParentId) {
    $result = [System.Collections.Generic.List[int]]::new()
    $children = @(Get-CimInstance Win32_Process -Filter "ParentProcessId = $ParentId")
    foreach ($child in $children) {
        foreach ($descendant in (Get-DescendantProcessIds -ParentId $child.ProcessId)) {
            $result.Add($descendant)
        }
        $result.Add([int]$child.ProcessId)
    }
    return $result
}

function Invoke-CloseLogWindows {
    if (-not $LabId -or -not $ProcessCsv) {
        throw 'CloseLogWindows requiere LabId y ProcessCsv.'
    }
    $closed = 0
    foreach ($token in ($ProcessCsv -split ',')) {
        if ($token -notmatch '^(\d+)@(\d+)$') {
            throw "Identidad de terminal no válida: $token"
        }
        $processId = [int]$Matches[1]
        $expectedStart = [long]$Matches[2]
        $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
        if (-not $process) {
            continue
        }
        $actualStart = $process.StartTime.ToUniversalTime().ToFileTimeUtc()
        if ($process.ProcessName -ne 'wsl' -or $actualStart -ne $expectedStart) {
            Write-Warning "No se cierra PID $processId porque ya no es la terminal registrada para $LabId."
            continue
        }
        foreach ($descendant in (Get-DescendantProcessIds -ParentId $processId)) {
            Stop-Process -Id $descendant -Force -ErrorAction SilentlyContinue
        }
        Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
        $closed += 1
    }
    Write-Host "[windows] $closed terminal(es) WSL de entidades cerradas"
}

try {
    switch ($Action) {
        'Check' { Invoke-Check }
        'NetworkUp' { Invoke-NetworkUp }
        'NetworkDown' { Invoke-NetworkDown }
        'NetworkStatus' { Invoke-NetworkStatus }
        'OpenLogWindows' { Invoke-OpenLogWindows }
        'CloseLogWindows' { Invoke-CloseLogWindows }
    }
    if ($ResultFile) {
        $message = if ($script:ResultMessage) {
            $script:ResultMessage
        }
        else {
            "operación elevada $Action completada"
        }
        $json = [pscustomobject]@{
            Success = $true
            Action = $Action
            Message = $message
            ErrorId = $null
        } | ConvertTo-Json -Compress
        [IO.File]::WriteAllText($ResultFile, $json, $Utf8NoBom)
    }
}
catch {
    if ($ResultFile) {
        $json = [pscustomobject]@{
            Success = $false
            Action = $Action
            Message = $_.Exception.Message
            ErrorId = [string]$_.FullyQualifiedErrorId
            Position = [string]$_.InvocationInfo.PositionMessage
        } | ConvertTo-Json -Compress
        [IO.File]::WriteAllText($ResultFile, $json, $Utf8NoBom)
        exit 1
    }
    [Console]::Error.WriteLine("[windows] ERROR: $($_.Exception.Message) [$($_.FullyQualifiedErrorId)]")
    exit 1
}
