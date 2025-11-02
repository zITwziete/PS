# Skrypt Synchronizacji Czasu Active Directory - Wersja Uproszczona
# Autor: zitwziete.org
# Strona: https://zitwziete.org
# GitHub: https://github.com/zITwziete/PS
# Wersja: 3.0

param(
    [string]$LogPath = "C:\Logs\TimeSync",
    [int]$AlertThresholdSeconds = 60,
    [switch]$Monitor,
    [int]$RefreshSeconds = 30
)

# Importuj modul AD
try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-Host "BLAD: Nie znaleziono modulu Active Directory. Zainstaluj RSAT-AD-PowerShell." -ForegroundColor Red
    exit 1
}

# Globalne serwery NTP
$Global:NTPServers = @(
    "0.pl.pool.ntp.org",
    "1.pl.pool.ntp.org",
    "time.windows.com",
    "time.nist.gov"
)

# Utworz katalog logow
if (!(Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logFile = Join-Path $LogPath "TimeSync_$(Get-Date -Format 'yyyyMMdd').log"
    "$timestamp [$Level] $Message" | Add-Content -Path $logFile
    
    $color = switch ($Level) {
        "INFO" { "Gray" }
        "WARNING" { "Yellow" }
        "ERROR" { "Red" }
        "SUCCESS" { "Green" }
        default { "White" }
    }
    
    Write-Host "$timestamp - $Message" -ForegroundColor $color
}

function Get-TimeStatus {
    Write-Host "`n========== SPRAWDZANIE SYNCHRONIZACJI CZASU ==========" -ForegroundColor Cyan
    
    $DCs = Get-ADDomainController -Filter * -ErrorAction SilentlyContinue
    if (!$DCs) {
        Write-Log "Nie udalo sie pobrac kontrolerow domeny" -Level "ERROR"
        return $null
    }
    
    $PDC = (Get-ADDomain).PDCEmulator
    $referenceTime = Get-Date
    
    Write-Host "Czas Referencyjny: $referenceTime" -ForegroundColor Yellow
    Write-Host "PDC Emulator: $PDC" -ForegroundColor Yellow
    Write-Host ""
    
    $results = @()
    
    foreach ($DC in $DCs) {
        Write-Host "Sprawdzanie $($DC.Name)..." -NoNewline
        
        try {
            $dcTime = Invoke-Command -ComputerName $DC.Name -ScriptBlock { 
                Get-Date 
            } -ErrorAction Stop
            
            $timeDiff = [Math]::Abs(($referenceTime - $dcTime).TotalSeconds)
            
            $source = Invoke-Command -ComputerName $DC.Name -ScriptBlock {
                $src = w32tm /query /source 2>$null
                if ($src) { $src.Trim() } else { "Nieznany" }
            } -ErrorAction SilentlyContinue
            
            if (!$source) { $source = "Nieznany" }
            
            $status = if ($timeDiff -lt 30) {
                "OK"
            }
            elseif ($timeDiff -lt $AlertThresholdSeconds) {
                "OSTRZEZENIE"
            }
            else {
                "KRYTYCZNY"
            }
            
            $results += [PSCustomObject]@{
                Serwer = $DC.Name
                Czas = $dcTime
                RoznicaSekund = [Math]::Round($timeDiff, 2)
                Zrodlo = $source
                Status = $status
                CzyPDC = ($DC.HostName -eq $PDC)
            }
            
            $statusColor = switch ($status) {
                "OK" { "Green" }
                "OSTRZEZENIE" { "Yellow" }
                "KRYTYCZNY" { "Red" }
            }
            
            Write-Host " [$status]" -ForegroundColor $statusColor
        }
        catch {
            Write-Host " [BLAD]" -ForegroundColor Red
            Write-Log "Nie udalo sie sprawdzic $($DC.Name): $_" -Level "ERROR"
            
            $results += [PSCustomObject]@{
                Serwer = $DC.Name
                Czas = $null
                RoznicaSekund = 999
                Zrodlo = "BLAD"
                Status = "OFFLINE"
                CzyPDC = ($DC.HostName -eq $PDC)
            }
        }
    }
    
    return $results
}

function Show-Results {
    param($Results)
    
    if (!$Results) { return }
    
    Write-Host "`n========== WYNIKI ==========" -ForegroundColor Cyan
    $Results | Format-Table -AutoSize
    
    $okCount = ($Results | Where-Object { $_.Status -eq "OK" }).Count
    $warningCount = ($Results | Where-Object { $_.Status -eq "OSTRZEZENIE" }).Count
    $criticalCount = ($Results | Where-Object { $_.Status -in @("KRYTYCZNY", "OFFLINE") }).Count
    
    Write-Host "`n========== PODSUMOWANIE ==========" -ForegroundColor Cyan
    Write-Host "Wszystkich DC: $($Results.Count)" -ForegroundColor White
    Write-Host "OK: $okCount" -ForegroundColor Green
    Write-Host "Ostrzezenia: $warningCount" -ForegroundColor Yellow
    Write-Host "Krytyczne/Offline: $criticalCount" -ForegroundColor Red
    
    if ($criticalCount -gt 0) {
        Write-Host "`nKRYTYCZNE: Wymagane natychmiastowe dzialanie!" -ForegroundColor Red -BackgroundColor DarkRed
        Write-Log "Wykryto KRYTYCZNE problemy z synchronizacja czasu na $criticalCount DC" -Level "ERROR"
    }
    elseif ($warningCount -gt 0) {
        Write-Host "`nOSTRZEZENIE: Wykryto roznice czasu" -ForegroundColor Yellow
        Write-Log "Ostrzezenia o rozbieznosci czasu na $warningCount DC" -Level "WARNING"
    }
    else {
        Write-Host "`nWszystkie systemy zsynchronizowane poprawnie" -ForegroundColor Green
        Write-Log "Wszystkie DC zsynchronizowane poprawnie" -Level "SUCCESS"
    }
}

function Set-PDCTimeSource {
    Write-Host "`nKonfigurowanie zrodla czasu PDC..." -ForegroundColor Yellow
    
    try {
        $PDC = (Get-ADDomain).PDCEmulator
        
        $scriptBlock = {
            param($servers)
            
            Stop-Service W32Time -Force
            
            $peerList = ($servers | ForEach-Object { "$_,0x8" }) -join ' '
            w32tm /config /manualpeerlist:"$peerList" /syncfromflags:manual /reliable:yes /update
            
            Start-Service W32Time
            w32tm /resync /rediscover
            
            return $?
        }
        
        $result = Invoke-Command -ComputerName $PDC -ScriptBlock $scriptBlock -ArgumentList (,$Global:NTPServers)
        
        if ($result) {
            Write-Host "Zrodlo czasu PDC skonfigurowane pomyslnie" -ForegroundColor Green
            Write-Log "Zrodlo czasu PDC skonfigurowane" -Level "SUCCESS"
        }
        else {
            throw "Polecenie konfiguracji nie powiodlo sie"
        }
    }
    catch {
        Write-Host "Nie udalo sie skonfigurowac PDC: $_" -ForegroundColor Red
        Write-Log "Nie udalo sie skonfigurowac PDC: $_" -Level "ERROR"
    }
}

function Reset-DCTimeSync {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DCName
    )
    
    Write-Host "`nResetowanie synchronizacji czasu na $DCName..." -ForegroundColor Yellow
    
    try {
        $PDC = (Get-ADDomain).PDCEmulator
        $isPDC = $DCName -eq $PDC.Split('.')[0]
        
        $scriptBlock = {
            param($isPDC, $servers)
            
            Stop-Service W32Time -Force
            w32tm /unregister
            w32tm /register
            
            if ($isPDC) {
                $peerList = ($servers | ForEach-Object { "$_,0x8" }) -join ' '
                w32tm /config /manualpeerlist:"$peerList" /syncfromflags:manual /reliable:yes /update
            }
            else {
                w32tm /config /syncfromflags:domhier /update
            }
            
            Start-Service W32Time
            w32tm /resync /rediscover
            
            return $?
        }
        
        $result = Invoke-Command -ComputerName $DCName -ScriptBlock $scriptBlock -ArgumentList $isPDC,(,$Global:NTPServers)
        
        if ($result) {
            Write-Host "Synchronizacja czasu zresetowana pomyslnie na $DCName" -ForegroundColor Green
            Write-Log "Zresetowano synchronizacje czasu na $DCName" -Level "SUCCESS"
        }
        else {
            throw "Polecenie resetowania nie powiodlo sie"
        }
    }
    catch {
        Write-Host "Nie udalo sie zresetowac ${DCName}: $_" -ForegroundColor Red
        Write-Log "Nie udalo sie zresetowac ${DCName}: $_" -Level "ERROR"
    }
}

function Start-Monitoring {
    param(
        [int]$RefreshInterval = 30
    )
    
    Write-Host "`nUruchamianie trybu monitorowania (odswiez co $RefreshInterval sekund)..." -ForegroundColor Green
    Write-Host "Nacisnij CTRL+C aby zatrzymac" -ForegroundColor Yellow
    Write-Host ""
    
    try {
        while ($true) {
            Clear-Host
            Write-Host "========== TRYB MONITOROWANIA CZASU AD ==========" -ForegroundColor Cyan
            Write-Host "Ostatnie odswiez: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
            Write-Host "Nastepne odswiez za: $RefreshInterval sekund" -ForegroundColor Gray
            
            $results = Get-TimeStatus
            Show-Results -Results $results
            
            Start-Sleep -Seconds $RefreshInterval
        }
    }
    catch {
        Write-Host "`nMonitorowanie zatrzymane przez uzytkownika" -ForegroundColor Yellow
        Write-Log "Monitorowanie zatrzymane" -Level "INFO"
    }
}

function Test-DomainTimeConnectivity {
    Write-Host "`nTestowanie lacza czasowego domeny..." -ForegroundColor Yellow
    
    try {
        # Pobierz kontrolery domeny
        Write-Host "Pobieranie kontrolerow domeny..." -ForegroundColor Gray
        $DCs = Get-ADDomainController -Filter * -ErrorAction Stop
        $PDC = (Get-ADDomain).PDCEmulator
        
        Write-Host "Znaleziono $($DCs.Count) kontrolerow domeny" -ForegroundColor Green
        Write-Host "PDC Emulator: $PDC`n" -ForegroundColor Green
        
        # Testuj polaczenie z kazdym DC
        foreach ($DC in $DCs) {
            Write-Host "Testowanie $($DC.Name)..." -NoNewline
            
            # Test ping
            $ping = Test-Connection -ComputerName $DC.Name -Count 1 -Quiet -ErrorAction SilentlyContinue
            if (!$ping) {
                Write-Host " BRAK ODPOWIEDZI" -ForegroundColor Red
                continue
            }
            
            # Test portu W32Time (UDP 123)
            $udpTest = Test-NetConnection -ComputerName $DC.Name -Port 123 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
            
            # Test zdalnego polaczenia
            try {
                $remoteTest = Invoke-Command -ComputerName $DC.Name -ScriptBlock {
                    $service = Get-Service W32Time
                    return $service.Status
                } -ErrorAction Stop
                
                if ($remoteTest -eq "Running") {
                    Write-Host " OK (Usluga dziala)" -ForegroundColor Green
                }
                else {
                    Write-Host " OSTRZEZENIE (Usluga: $remoteTest)" -ForegroundColor Yellow
                }
            }
            catch {
                Write-Host " BLAD (Brak dostepu zdalnego)" -ForegroundColor Red
            }
        }
        
        # Test synchronizacji czasu
        Write-Host "`nTestowanie synchronizacji czasu..." -ForegroundColor Yellow
        $w32tmResult = w32tm /query /source 2>&1
        Write-Host "Aktualne zrodlo: $w32tmResult" -ForegroundColor Cyan
        
        $statusResult = w32tm /query /status 2>&1
        Write-Host "`nStatus synchronizacji:" -ForegroundColor Yellow
        Write-Host $statusResult -ForegroundColor Gray
    }
    catch {
        Write-Host "BLAD podczas testowania lacza: $_" -ForegroundColor Red
        Write-Log "Blad testowania lacza domeny: $_" -Level "ERROR"
    }
}

function Configure-DomainMemberTimeSync {
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )
    
    Write-Host "`nKonfigurowanie synchronizacji czasu dla czlonka domeny: $ComputerName" -ForegroundColor Yellow
    
    try {
        $scriptBlock = {
            # Zatrzymaj usluge W32Time
            Stop-Service W32Time -Force
            
            # Skonfiguruj synchronizacje z hierarchia domeny
            w32tm /config /syncfromflags:domhier /update
            
            # Ustaw typ uruchomienia na automatyczny
            Set-Service W32Time -StartupType Automatic
            
            # Uruchom usluge
            Start-Service W32Time
            
            # Wymus synchronizacje
            w32tm /resync /rediscover
            
            # Sprawdz status
            $status = w32tm /query /status
            return @{
                Success = $?
                Status = $status
            }
        }
        
        if ($ComputerName -eq $env:COMPUTERNAME) {
            Write-Host "Konfigurowanie komputera lokalnego..." -ForegroundColor Gray
            $result = & $scriptBlock
        }
        else {
            Write-Host "Konfigurowanie komputera zdalnego: $ComputerName..." -ForegroundColor Gray
            $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ErrorAction Stop
        }
        
        if ($result.Success) {
            Write-Host "SUKCES: Synchronizacja czasu skonfigurowana pomyslnie na $ComputerName!" -ForegroundColor Green
            Write-Host "`nStatus synchronizacji:" -ForegroundColor Yellow
            Write-Host $result.Status -ForegroundColor Gray
            Write-Log "Synchronizacja czasu czlonka domeny skonfigurowana na $ComputerName" -Level "SUCCESS"
        }
        else {
            throw "Konfiguracja nie powiodla sie na $ComputerName"
        }
    }
    catch {
        Write-Host "BLAD: Nie udalo sie skonfigurowac ${ComputerName}: $_" -ForegroundColor Red
        Write-Log "Nie udalo sie skonfigurowac czlonka domeny ${ComputerName}: $_" -Level "ERROR"
        
        Write-Host "`nWskazowki rozwiazywania problemow:" -ForegroundColor Yellow
        Write-Host "1. Upewnij sie, ze komputer jest dolaczony do domeny" -ForegroundColor Gray
        Write-Host "2. Sprawdz czy mozesz polaczyc sie zdalnie z komputerem" -ForegroundColor Gray
        Write-Host "3. Zweryfikuj czy usluga W32Time jest zainstalowana" -ForegroundColor Gray
        Write-Host "4. Sprawdz zasady zapory domeny dla W32Time" -ForegroundColor Gray
    }
}

function Repair-W32TimeService {
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )
    
    Write-Host "`nNaprawa uslugi W32Time na: $ComputerName" -ForegroundColor Yellow
    Write-Host "To naprawia zatrzymane lub uszkodzone uslugi W32Time`n" -ForegroundColor Gray
    
    try {
        $scriptBlock = {
            param($servers)
            
            Write-Host "Krok 1: Zatrzymywanie uslugi W32Time..." -ForegroundColor Gray
            Stop-Service W32Time -Force -ErrorAction SilentlyContinue
            
            Write-Host "Krok 2: Wyrejestrowywanie uslugi..." -ForegroundColor Gray
            w32tm /unregister
            
            Write-Host "Krok 3: Rejestrowanie uslugi..." -ForegroundColor Gray
            w32tm /register
            
            Write-Host "Krok 4: Uruchamianie uslugi..." -ForegroundColor Gray
            Start-Service W32Time -ErrorAction Stop
            
            Write-Host "Krok 5: Sprawdzanie statusu uslugi..." -ForegroundColor Gray
            Start-Sleep -Seconds 2
            
            $service = Get-Service W32Time
            if ($service.Status -eq "Running") {
                # Konfiguracja w zaleznosci od roli PDC
                $PDC = (Get-ADDomain).PDCEmulator
                if ($env:COMPUTERNAME -eq $PDC.Split('.')[0]) {
                    $peerList = ($servers | ForEach-Object { "$_,0x8" }) -join ' '
                    w32tm /config /manualpeerlist:"$peerList" /syncfromflags:manual /reliable:yes /update
                }
                else {
                    w32tm /config /syncfromflags:domhier /update
                }
                w32tm /resync /rediscover
                return $true
            }
            return $false
        }
        
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ArgumentList (,$Global:NTPServers)
        
        if ($result) {
            Write-Host "SUKCES: Usluga W32Time naprawiona na $ComputerName!" -ForegroundColor Green
            Write-Log "Usluga W32Time pomyslnie naprawiona na $ComputerName" -Level "SUCCESS"
            return $true
        }
        else {
            throw "Nie udalo sie naprawic W32Time na $ComputerName"
        }
    }
    catch {
        Write-Host "BLAD: Nie udalo sie naprawic uslugi W32Time: $_" -ForegroundColor Red
        Write-Log "Nie udalo sie naprawic W32Time: $_" -Level "ERROR"
        
        Write-Host "`nWskazowki rozwiazywania problemow:" -ForegroundColor Yellow
        Write-Host "1. Upewnij sie, ze uruchamiasz PowerShell jako Administrator" -ForegroundColor Gray
        Write-Host "2. Sprawdz Dziennik zdarzen dla bledow W32Time" -ForegroundColor Gray
        Write-Host "3. Sprobuj uruchomic: sfc /scannow" -ForegroundColor Gray
        Write-Host "4. Rozwaz ponowne uruchomienie serwera" -ForegroundColor Gray
        
        return $false
    }
}

function Show-Menu {
    Write-Host "`n========== MENEDZER SYNCHRONIZACJI CZASU AD ==========" -ForegroundColor Cyan
    Write-Host "1. Sprawdz status synchronizacji czasu"
    Write-Host "2. Skonfiguruj zrodlo czasu PDC"
    Write-Host "3. Zresetuj konfiguracje czasu DC"
    Write-Host "4. Wymus synchronizacje calej domeny"
    Write-Host "5. Uruchom tryb monitorowania"
    Write-Host "6. Testuj lacznosc NTP"
    Write-Host "7. Napraw usluge W32Time (napraw zatrzymana/uszkodzona usluge)"
    Write-Host "8. Skonfiguruj czlonka domeny (dla stacji roboczych/serwerow)"
    Write-Host "0. Wyjscie"
    Write-Host ""
    
    $choice = Read-Host "Wybierz opcje (0-8)"
    
    switch ($choice) {
        "1" {
            $results = Get-TimeStatus
            Show-Results -Results $results
        }
        "2" {
            Set-PDCTimeSource
        }
        "3" {
            $dc = Read-Host "Podaj nazwe DC"
            if ($dc) {
                Reset-DCTimeSync -DCName $dc
            }
        }
        "4" {
            Write-Host "`nWymuszanie synchronizacji calej domeny..." -ForegroundColor Yellow
            $DCs = Get-ADDomainController -Filter *
            foreach ($DC in $DCs) {
                Write-Host "Synchronizacja $($DC.Name)..." -NoNewline
                try {
                    Invoke-Command -ComputerName $DC.Name -ScriptBlock {
                        w32tm /resync /rediscover
                    } -ErrorAction Stop
                    Write-Host " OK" -ForegroundColor Green
                }
                catch {
                    Write-Host " NIEPOWODZENIE" -ForegroundColor Red
                }
            }
        }
        "5" {
            Start-Monitoring -RefreshInterval $RefreshSeconds
        }
        "6" {
            Write-Host "`nTestowanie lacznosci NTP..." -ForegroundColor Yellow
            foreach ($server in $Global:NTPServers) {
                Write-Host "  $server..." -NoNewline
                $result = w32tm /stripchart /computer:$server /dataonly /samples:1 2>&1
                if ($result -match "error|0x800") {
                    Write-Host " NIEPOWODZENIE" -ForegroundColor Red
                }
                else {
                    Write-Host " OK" -ForegroundColor Green
                }
            }
        }
        "7" {
            Write-Host "`nOpcje naprawy uslugi W32Time:" -ForegroundColor Cyan
            Write-Host "1. Napraw lokalna usluge W32Time (ten komputer)"
            Write-Host "2. Napraw W32Time na konkretnym DC"
            Write-Host "3. Napraw W32Time na wszystkich DC"
            Write-Host ""
            
            $repairChoice = Read-Host "Wybierz opcje naprawy (1-3)"
            
            switch ($repairChoice) {
                "1" {
                    Repair-W32TimeService
                }
                "2" {
                    $dc = Read-Host "Podaj nazwe DC"
                    if ($dc) {
                        Repair-W32TimeService -ComputerName $dc
                    }
                }
                "3" {
                    Write-Host "`nNaprawa W32Time na wszystkich DC..." -ForegroundColor Yellow
                    $DCs = Get-ADDomainController -Filter *
                    foreach ($DC in $DCs) {
                        Write-Host "`n--- Przetwarzanie $($DC.Name) ---" -ForegroundColor Cyan
                        Repair-W32TimeService -ComputerName $DC.Name
                    }
                }
                default {
                    Write-Host "Nieprawidlowy wybor" -ForegroundColor Red
                }
            }
        }
        "8" {
            Write-Host "`nKonfiguracja synchronizacji czasu czlonka domeny:" -ForegroundColor Cyan
            Write-Host "1. Skonfiguruj TEN komputer (lokalny)"
            Write-Host "2. Skonfiguruj komputer zdalny"
            Write-Host "3. Skonfiguruj wiele komputerow z listy"
            Write-Host "4. Testuj lacznosc czasu domeny z tego komputera"
            Write-Host ""
            
            $memberChoice = Read-Host "Wybierz opcje (1-4)"
            
            switch ($memberChoice) {
                "1" {
                    Configure-DomainMemberTimeSync
                }
                "2" {
                    $computer = Read-Host "Podaj nazwe komputera"
                    if ($computer) {
                        Configure-DomainMemberTimeSync -ComputerName $computer
                    }
                }
                "3" {
                    Write-Host "Podaj nazwy komputerow (jedna na linie, pusta linia aby zakonczyc):" -ForegroundColor Yellow
                    $computers = @()
                    while ($true) {
                        $comp = Read-Host
                        if ([string]::IsNullOrWhiteSpace($comp)) { break }
                        $computers += $comp
                    }
                    
                    if ($computers.Count -gt 0) {
                        Write-Host "`nKonfigurowanie $($computers.Count) komputerow..." -ForegroundColor Yellow
                        foreach ($comp in $computers) {
                            Write-Host "`n--- Przetwarzanie $comp ---" -ForegroundColor Cyan
                            Configure-DomainMemberTimeSync -ComputerName $comp
                        }
                    }
                }
                "4" {
                    Test-DomainTimeConnectivity
                }
                default {
                    Write-Host "Nieprawidlowy wybor" -ForegroundColor Red
                }
            }
        }
        "0" {
            Write-Host "Zamykanie..." -ForegroundColor Gray
            return
        }
        default {
            Write-Host "Nieprawidlowy wybor" -ForegroundColor Red
        }
    }
    
    # Pokaz menu ponownie, chyba ze wychodzisz lub monitorujesz
    if ($choice -ne "0" -and $choice -ne "5") {
        Show-Menu
    }
}

# Glowne wykonanie
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "   Narzedzie Synchronizacji Czasu Active Directory" -ForegroundColor Cyan
Write-Host "                   Wersja 3.0" -ForegroundColor Cyan
Write-Host "             Autor: zitwziete.org" -ForegroundColor Cyan
Write-Host "        https://github.com/zITwziete/PS" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# Sprawdz uprawnienia administratora
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "`nOSTRZEZENIE: Ten skrypt wymaga uprawnien administratora!" -ForegroundColor Red
    Write-Host "Prosze uruchomic PowerShell jako Administrator." -ForegroundColor Yellow
    exit 1
}

Write-Log "Narzedzie synchronizacji czasu AD uruchomione" -Level "INFO"

# Sprawdz czy zaczeto tryb monitorowania
if ($Monitor) {
    Start-Monitoring -RefreshInterval $RefreshSeconds
}
else {
    # Wykonaj poczatkowe sprawdzenie
    $results = Get-TimeStatus
    Show-Results -Results $results
    
    # Pokaz menu
    Show-Menu
}

Write-Log "Narzedzie synchronizacji czasu AD zakonczone" -Level "INFO"
Write-Host "`nLog zapisany w: $LogPath" -ForegroundColor Gray
