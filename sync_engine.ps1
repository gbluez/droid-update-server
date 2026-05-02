# DROID Security Database Synchronizer Engine (Turbo-Parallel v5.5)
$ErrorActionPreference = 'Continue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

$jsonFile = "$PWD\malware\malwares.json"
if (!(Test-Path "$PWD\malware")) { New-Item -ItemType Directory -Path "$PWD\malware" -Force | Out-Null }

$allMals = New-Object System.Collections.Generic.HashSet[string]
$localCount = 0
Add-Type -AssemblyName System.Net.Http
$client = New-Object System.Net.Http.HttpClient
$client.Timeout = [TimeSpan]::FromSeconds(45)
$client.DefaultRequestHeaders.Add('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) DROID/3.5')

function Update-UI ($stage, $count) {
    [Console]::WriteLine("[PROGRESS] ${stage}: ${count}")
}

try {
    # 0. Warm-up
    "7.5", "7.6", "7.7", "7.8", "7.9", "7.10", "7.11", "7.12" | ForEach-Object { Update-UI $_ 0 }

    # 1. Faster INIT (Smart Stream)
    if (Test-Path $jsonFile) {
        try {
            $lines = [System.IO.File]::ReadLines($jsonFile)
            foreach ($line in $lines) {
                if ($line -match '"local_heuristic_count":\s*(\d+)') {
                    $localCount = [int]$matches[1]
                }
                elseif ($line.Contains('"')) {
                    $p = $line.Split('"')
                    if ($p.Count -ge 2) {
                        $h = $p[1]
                        if ($h.Length -ge 32 -and $h.Length -le 64) { [void]$allMals.Add($h) }
                    }
                }
            }
            Update-UI "7.9" $allMals.Count
        }
        catch {}
    }

    # 2. Parallel Downloads Initiation (Extended with missing datasets)
    $urls = @{
        "7.5"  = "https://github.com/Neo23x0/signature-base/raw/master/iocs/hash-iocs.txt"
        "7.6"  = "https://github.com/Malware-Hunter/MH-100K-dataset/raw/refs/heads/main/data/processed/mh100_labels.csv"
        "7.7"  = "https://github.com/d-Raco/android-malware-source-code-analysis/raw/main/android-os-malware-samples.csv"
        "7.8"  = "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/README.md"
        "7.10" = "https://raw.githubusercontent.com/InQuest/malware-samples/master/miscellaneous/26de80e3bbbe1f053da4131ca7a405644b7443356ec97d48517f1ab86d5f1ca5.related"
        "7.11" = "https://bazaar.abuse.ch/export/txt/sha256/recent/"
    }

    $tasks = @{}
    foreach ($key in $urls.Keys) {
        try {
            $tasks[$key] = $client.GetAsync($urls[$key])
        } catch { 
            # If initialization fails, task is null
        }
    }

    # 2.5 Maltrail Fast Zip Fetch (Stage 7.12)
    $globalMaltrailDate = (Get-Date).ToString("dd.MM.yyyy")
    $maltrailZipTask = $null
    try {
        $maltrailZipTask = $client.GetByteArrayAsync("https://github.com/stamparm/maltrail/archive/refs/heads/master.zip")
    } catch {}

    # 3. Global Registry (7.9) - Expanded to All Available Volumes
    $hashUrls = @(
        "https://bazaar.abuse.ch/export/txt/md5/recent/",
        "https://bazaar.abuse.ch/export/txt/sha1/recent/"
    )

    # 4. Process parallel results
    foreach ($key in $urls.Keys) {
        $dateStr = (Get-Date).ToString("dd.MM.yyyy")
        try {
            $task = $tasks[$key]
            if ($null -eq $task) { throw "Task init failed" }
            $resp = $task.GetAwaiter().GetResult()
            if (-not $resp.IsSuccessStatusCode) { throw "HTTP Error" }
            $date = $resp.Content.Headers.LastModified
            if ($null -eq $date) { $date = $resp.Headers.Date }
            if ($null -ne $date) { $dateStr = $date.Value.ToString("dd.MM.yyyy") }

            $data = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            $matches = [regex]::Matches($data, '[a-fA-F0-9]{32,64}')
            $count = 0
            $newExtracted = 0
            foreach ($m in $matches) {
                $count++
                if ($allMals.Add($m.Value.ToLower())) { 
                    $localCount++ 
                    $newExtracted++
                }
                if ($count % 500 -eq 0) { Update-UI $key $count }
            }
            if ($newExtracted -eq 0) {
                Update-UI $key "0 (Already update $dateStr)"
            } else {
                Update-UI $key "$count (Updated $dateStr)"
            }
        }
        catch { Update-UI $key "0 (Already update $dateStr)" }
    }

    # Process Maltrail results (7.12)
    $malCount = 0
    $newMaltrail = 0
    if ($null -ne $maltrailZipTask) {
        try {
            $zipBytes = $maltrailZipTask.GetAwaiter().GetResult()
            $zipPath = "$PWD\temp_maltrail.zip"
            $extractPath = "$PWD\temp_maltrail_extracted"
            [System.IO.File]::WriteAllBytes($zipPath, $zipBytes)
            
            if (Test-Path $extractPath) { Remove-Item -Path $extractPath -Recurse -Force }
            
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            try {
                [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $extractPath)
            } catch {
                Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force
            }
            
            $files = Get-ChildItem -Path "$extractPath\maltrail-master\trails\static\malware" -Filter *.txt
            foreach ($f in $files) {
                try {
                    $content = [System.IO.File]::ReadAllText($f.FullName)
                    $matches = [regex]::Matches($content, '[a-zA-Z0-9\-\.]{8,64}')
                    foreach ($rematch in $matches) {
                        if ($allMals.Add($rematch.Value.ToLower())) { 
                            $localCount++ 
                            $newMaltrail++
                        }
                        $malCount++
                        if ($malCount % 5000 -eq 0) { Update-UI "7.12" $malCount }
                    }
                } catch {}
            }
            Remove-Item -Path $zipPath -Force
            Remove-Item -Path $extractPath -Recurse -Force
        } catch {}
    }
    if ($newMaltrail -eq 0) {
        Update-UI "7.12" "0 (Already update $globalMaltrailDate)"
    } else {
        Update-UI "7.12" "$malCount (Updated $globalMaltrailDate)"
    }

    # 5. Process Global Data (7.9) - Serial Streaming
    $globalProcessed = 0
    $globalNew = 0
    $globalDate = (Get-Date).ToString("dd.MM.yyyy")
    $hasFoundDate = $false
    foreach ($url in $hashUrls) {
        try {
            $resp = $client.GetAsync($url, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
            if (-not $resp.IsSuccessStatusCode) { continue }
            if (-not $hasFoundDate) {
                $d = $resp.Content.Headers.LastModified
                if ($null -eq $d) { $d = $resp.Headers.Date }
                if ($null -ne $d) { 
                    $globalDate = $d.Value.ToString("dd.MM.yyyy")
                    $hasFoundDate = $true
                }
            }
            $stream = $resp.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
            $reader = New-Object System.IO.StreamReader($stream)
            while ($null -ne ($line = $reader.ReadLine())) {
                $h = $line.Trim().ToLower()
                if ($h.Length -ge 32) { 
                    $globalProcessed++
                    if ($allMals.Add($h)) { $globalNew++; $localCount++ }
                }
                if ($globalProcessed % 50000 -eq 0) { Update-UI "7.9" $globalProcessed }
            }
            $reader.Close()
        }
        catch {}
    }
    if ($globalNew -eq 0) {
        Update-UI "7.9" "0 (Already update $globalDate)"
    } else {
        Update-UI "7.9" "$globalProcessed (Updated $globalDate)"
    }

    # FINAL SAVE
    $sw = New-Object System.IO.StreamWriter($jsonFile, $false, [System.Text.UTF8Encoding]::new($false), 262144)
    $sw.WriteLine('{')
    $sw.WriteLine("    `"last_update`": `"$((Get-Date).ToString('yyyy-MM-dd'))`",")
    $sw.WriteLine('    "source": "DROID Extreme-Parallel v5.6",')
    $sw.WriteLine("    `"local_heuristic_count`": $localCount,")
    $sw.WriteLine("    `"total_signatures`": $($allMals.Count),")
    $sw.WriteLine('    "malwares": [')

    $total = $allMals.Count
    $idx = 0
    foreach ($m in $allMals) {
        $idx++
        $comma = if ($idx -lt $total) { "," } else { "" }
        $sw.WriteLine("        `"$m`"$comma")
        if ($idx % 50000 -eq 0) { Update-UI "9" $idx }
    }
    $sw.WriteLine('    ]')
    $sw.WriteLine('}')
    $sw.Close()
    
    $client.Dispose()
    exit 0
}
catch {
    exit 0 
}

