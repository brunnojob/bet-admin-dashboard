$ErrorActionPreference = "Stop"

# Comece com 1 para verificar o fluxo.
$TotalPRs = 1
$MockFile = "mock_betting_sessions.csv"

# Conforme sua última escolha: brunnojob como coautor.
$CoAuthorTag = "Co-authored-by: brunnojob <contato@brunnodev.store>"

function Invoke-Checked {
    param(
        [string]$Program,
        [string[]]$Arguments
    )

    & $Program @Arguments

    if ($LASTEXITCODE -ne 0) {
        throw "$Program falhou com código $LASTEXITCODE. Operação interrompida."
    }
}

$Games = @("Mines", "Crash", "Roulette", "Double", "Slots")
$Statuses = @("Win", "Loss")
$MessageFile = [System.IO.Path]::GetTempFileName()

try {
    Invoke-Checked "gh" @("auth", "status")
    Invoke-Checked "git" @("diff", "--exit-code")
    Invoke-Checked "git" @("diff", "--cached", "--exit-code")

    for ($i = 1; $i -le $TotalPRs; $i++) {
        $SessionID = [guid]::NewGuid().ToString("N")
        $BranchName = "data-feed-$SessionID"

        Invoke-Checked "git" @("switch", "main")
        Invoke-Checked "git" @("pull", "--ff-only", "origin", "main")
        Invoke-Checked "git" @("switch", "-c", $BranchName)

        if (-not (Test-Path -LiteralPath $MockFile)) {
            $Header = "SessionID,Game,BetAmount,Multiplier,Status,Timestamp"
            Set-Content -LiteralPath $MockFile -Value $Header -Encoding UTF8
        }

        $RandomGame = Get-Random -InputObject $Games
        $RandomBet = Get-Random -Minimum 10 -Maximum 5000
        $RandomMult = Get-Random -Minimum 10 -Maximum 100
        $RandomStatus = Get-Random -InputObject $Statuses
        $TimeLog = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        $NewRow = "$SessionID,$RandomGame,$RandomBet,$RandomMult,$RandomStatus,$TimeLog"

        Add-Content -LiteralPath $MockFile -Value $NewRow -Encoding UTF8
        Write-Host "[$i/$TotalPRs] Sessão simulada: $NewRow" -ForegroundColor Yellow

        $CommitMessage = @"
test(data): add mock betting session $SessionID

Add a simulated session for dashboard analytics testing.

$CoAuthorTag
"@

        Set-Content -LiteralPath $MessageFile -Value $CommitMessage -Encoding UTF8

        Invoke-Checked "git" @("add", "--", $MockFile)
        Invoke-Checked "git" @("commit", "-F", $MessageFile)
        Invoke-Checked "git" @("push", "-u", "origin", $BranchName)

        $PRTitle = "test(data): add mock betting session $SessionID"
        $PRBody = "Adiciona uma sessão simulada de $RandomGame para testes."

        Invoke-Checked "gh" @(
            "pr", "create",
            "--title", $PRTitle,
            "--body", $PRBody,
            "--base", "main",
            "--head", $BranchName
        )

        Invoke-Checked "gh" @(
            "pr", "merge", $BranchName,
            "--merge", "--delete-branch"
        )

        # Confirma que o merge ocorreu antes de continuar.
        $State = Invoke-Checked "gh" @(
            "pr", "view", $BranchName,
            "--json", "state",
            "--jq", ".state"
        )

        if ("$State".Trim() -ne "MERGED") {
            throw "O PR ainda não foi mesclado. Verifique os checks no GitHub."
        }

        Invoke-Checked "git" @("switch", "main")
        Invoke-Checked "git" @("pull", "--ff-only", "origin", "main")

        Write-Host "PR $i mesclado com sucesso." -ForegroundColor Green

        if ($i -lt $TotalPRs) {
            Start-Sleep -Seconds 12
        }
    }
}
finally {
    Remove-Item -LiteralPath $MessageFile -ErrorAction SilentlyContinue
}