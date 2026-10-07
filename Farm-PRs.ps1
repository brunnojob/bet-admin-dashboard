$ErrorActionPreference = "Stop"

# Ajuste para a quantidade restante se já concluiu alguns PRs.
$TotalPRs = 601

$IntervaloEntrePRs = 60
$IntervaloEntreChamadas = 3

$MockFile = "mock_betting_sessions.csv"

$AuthorName = "brunnojob"
$AuthorEmail = "contato@brunnodev.store"
$CoAuthorTag = "Co-authored-by: ineedfoundmyway <329826984+ineedfoundmyway@users.noreply.github.com>"

function Invoke-Checked {
    param(
        [string]$Program,
        [string[]]$Arguments
    )

    if ($Program -eq "gh") {
        Start-Sleep -Seconds $IntervaloEntreChamadas
    }

    & $Program @Arguments
    $ExitCode = $LASTEXITCODE

    if ($ExitCode -ne 0) {
        throw @"
$Program falhou com código $ExitCode.
A automação foi interrompida. Confira a mensagem acima.
Se houver rate limit, respeite o prazo informado pelo GitHub.
Confira a branch e o PR existentes antes de executar novamente.
"@
    }
}

$Games = @("Mines", "Crash", "Roulette", "Double", "Slots")
$Statuses = @("Win", "Loss")

$MessageFile = [System.IO.Path]::GetTempFileName()
$BodyFile = [System.IO.Path]::GetTempFileName()

try {
    Invoke-Checked "gh" @("auth", "status")

    Write-Host "Repositório de destino:" -ForegroundColor Cyan
    Invoke-Checked "git" @("remote", "get-url", "origin")

    # Configura a identidade somente neste repositório.
    Invoke-Checked "git" @(
        "config", "--local", "user.name", $AuthorName
    )

    Invoke-Checked "git" @(
        "config", "--local", "user.email", $AuthorEmail
    )

    Write-Host "Autor: $AuthorName <$AuthorEmail>" -ForegroundColor Cyan
    Write-Host "Coautor: ineedfoundmyway" -ForegroundColor Cyan

    # Interrompe se houver alterações em arquivos rastreados.
    Invoke-Checked "git" @("diff", "--exit-code")
    Invoke-Checked "git" @("diff", "--cached", "--exit-code")

    Write-Host "Iniciando $TotalPRs PRs com dados simulados." -ForegroundColor Cyan

    for ($i = 1; $i -le $TotalPRs; $i++) {
        $SessionID = [guid]::NewGuid().ToString("N")
        $BranchName = "data-feed-$SessionID"

        Invoke-Checked "git" @("switch", "main")
        Invoke-Checked "git" @("pull", "--ff-only", "origin", "main")
        Invoke-Checked "git" @("switch", "-c", $BranchName)

        if (-not (Test-Path -LiteralPath $MockFile)) {
            $Header = "SessionID,Game,BetAmount,Multiplier,Status,Timestamp"

            Set-Content `
                -LiteralPath $MockFile `
                -Value $Header `
                -Encoding UTF8
        }

        $RandomGame = Get-Random -InputObject $Games
        $RandomBet = Get-Random -Minimum 10 -Maximum 5000
        $RandomMult = Get-Random -Minimum 10 -Maximum 100
        $RandomStatus = Get-Random -InputObject $Statuses
        $TimeLog = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        $NewRow = "$SessionID,$RandomGame,$RandomBet,$RandomMult,$RandomStatus,$TimeLog"

        Add-Content `
            -LiteralPath $MockFile `
            -Value $NewRow `
            -Encoding UTF8

        Write-Host "[$i/$TotalPRs] Sessão simulada: $NewRow" -ForegroundColor Yellow

        $CommitMessage = @"
test(data): add mock betting session $SessionID

Add a simulated session for dashboard analytics testing.

$CoAuthorTag
"@

        Set-Content `
            -LiteralPath $MessageFile `
            -Value $CommitMessage `
            -Encoding UTF8

        Invoke-Checked "git" @("add", "--", $MockFile)

        Invoke-Checked "git" @(
            "commit",
            "--author", "$AuthorName <$AuthorEmail>",
            "-F", $MessageFile
        )

        $HeadSha = Invoke-Checked "git" @("rev-parse", "HEAD")
        $HeadSha = "$HeadSha".Trim()

        Invoke-Checked "git" @(
            "push", "-u", "origin", $BranchName
        )

        $PRTitle = "test(data): add mock betting session $SessionID"
        $PRBody = "Adiciona uma sessão simulada de $RandomGame para testes."

        Set-Content `
            -LiteralPath $BodyFile `
            -Value $PRBody `
            -Encoding UTF8

        $PRUrl = Invoke-Checked "gh" @(
            "pr", "create",
            "--title", $PRTitle,
            "--body-file", $BodyFile,
            "--base", "main",
            "--head", $BranchName
        )

        $PRUrl = "$PRUrl".Trim()

        if ($PRUrl -notmatch "^https://github\.com/[^/]+/[^/]+/pull/\d+$") {
            throw "Não foi possível identificar a URL do PR criado. Confira o GitHub."
        }

        Write-Host "PR criado: $PRUrl" -ForegroundColor Cyan

        Invoke-Checked "gh" @(
            "pr", "merge", $PRUrl,
            "--merge",
            "--delete-branch",
            "--match-head-commit", $HeadSha
        )

        $State = Invoke-Checked "gh" @(
            "pr", "view", $PRUrl,
            "--json", "state",
            "--jq", ".state"
        )

        if ("$State".Trim() -ne "MERGED") {
            throw "O PR ainda não foi mesclado. Confira os checks ou a fila: $PRUrl"
        }

        Invoke-Checked "git" @("switch", "main")
        Invoke-Checked "git" @("pull", "--ff-only", "origin", "main")

        Write-Host "PR $i de $TotalPRs mesclado." -ForegroundColor Green

        if ($i -lt $TotalPRs) {
            Write-Host "Aguardando $IntervaloEntrePRs segundos..." -ForegroundColor Cyan
            Start-Sleep -Seconds $IntervaloEntrePRs
        }
    }

    Write-Host "Execução concluída." -ForegroundColor Green
}
finally {
    Remove-Item -LiteralPath $MessageFile -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $BodyFile -ErrorAction SilentlyContinue
}