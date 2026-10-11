$outDir = "c:\Users\frank\OneDrive\Desktop\Veil\app\ui\assets\logos"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$urls = @{
    "openai" = @(
        "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/png/openai.png",
        "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/openai.png"
    )
    "anthropic" = @(
        "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/png/anthropic.png",
        "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/anthropic.png"
    )
    "claude_code" = @(
        "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/png/claude.png",
        "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/claude.png"
    )
    "cursor" = @(
        "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/png/cursor.png",
        "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/cursor.png"
    )
    "antigravity" = @(
        "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/png/google.png",
        "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/google.png"
    )
    "system_env" = @(
        "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/png/powershell.png",
        "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/terminal.png"
    )
    "opencode" = @(
        "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/png/visual-studio-code.png",
        "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/vscode.png"
    )
}

foreach ($key in $urls.Keys) {
    $targetFile = Join-Path $outDir "$key.png"
    $success = $false
    foreach ($u in $urls[$key]) {
        try {
            Invoke-WebRequest -Uri $u -OutFile $targetFile -UseBasicParsing -TimeoutSec 10
            $size = (Get-Item $targetFile).Length
            if ($size -gt 500) {
                Write-Host "[OK] $key downloaded from $u ($size bytes)"
                $success = $true
                break
            }
        } catch {
            Write-Host "[FAIL] $key from $u : $_"
        }
    }
    if (-not $success) {
        Write-Host "[NOT FOUND] $key"
    }
}
