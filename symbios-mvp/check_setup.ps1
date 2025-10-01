# Symbios Network Setup Verification Script

Write-Host "🔍 Symbios Network Setup Verification" -ForegroundColor Green
Write-Host "=====================================" -ForegroundColor Green
Write-Host ""

# Check Rust
Write-Host "📦 Checking Rust installation..." -ForegroundColor Yellow
try {
    $rustVersion = & "C:\Users\$env:USERNAME\.cargo\bin\rustc.exe" --version 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Rust: $rustVersion" -ForegroundColor Green
    } else {
        Write-Host "❌ Rust not found or not working" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ Rust not found" -ForegroundColor Red
}

# Check Cargo
try {
    $cargoVersion = & "C:\Users\$env:USERNAME\.cargo\bin\cargo.exe" --version 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Cargo: $cargoVersion" -ForegroundColor Green
    } else {
        Write-Host "❌ Cargo not found or not working" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ Cargo not found" -ForegroundColor Red
}

# Check MSVC
Write-Host "" -ForegroundColor White
Write-Host "🔧 Checking MSVC Build Tools..." -ForegroundColor Yellow

$msvcFound = $false
$linkFound = $false

# Check for cl.exe
try {
    $clOutput = cl.exe 2>$null
    if ($LASTEXITCODE -eq 0 -or $clOutput -match "Microsoft") {
        Write-Host "✅ MSVC Compiler (cl.exe) found" -ForegroundColor Green
        $msvcFound = $true
    }
} catch {
    Write-Host "❌ MSVC Compiler (cl.exe) not found" -ForegroundColor Red
}

# Check for link.exe
try {
    $linkOutput = link.exe 2>$null
    if ($LASTEXITCODE -eq 0 -or $linkOutput -match "Microsoft") {
        Write-Host "✅ MSVC Linker (link.exe) found" -ForegroundColor Green
        $linkFound = $true
    }
} catch {
    Write-Host "❌ MSVC Linker (link.exe) not found" -ForegroundColor Red
}

# Try to compile a simple test
Write-Host "" -ForegroundColor White
Write-Host "🧪 Testing compilation..." -ForegroundColor Yellow

if ($msvcFound -and $linkFound) {
    try {
        Write-Host "Attempting to compile Symbios project..." -ForegroundColor White
        Push-Location
        Set-Location "D:\проекты\symbios\symbios-mvp"

        $checkResult = & "C:\Users\$env:USERNAME\.cargo\bin\cargo.exe" check 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ Compilation successful!" -ForegroundColor Green
            Write-Host "🚀 You can now run benchmarks!" -ForegroundColor Green
            Write-Host "" -ForegroundColor White
            Write-Host "To run benchmarks:" -ForegroundColor Cyan
            Write-Host "  .\run_benchmark.ps1" -ForegroundColor White
            Write-Host "" -ForegroundColor White
            Write-Host "To run full benchmarks:" -ForegroundColor Cyan
            Write-Host "  cargo bench" -ForegroundColor White
        } else {
            Write-Host "❌ Compilation failed" -ForegroundColor Red
            Write-Host "Error details:" -ForegroundColor Red
            Write-Host $checkResult -ForegroundColor Red
        }

        Pop-Location
    } catch {
        Write-Host "❌ Error during compilation test: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "❌ Cannot test compilation - MSVC tools missing" -ForegroundColor Red
    Write-Host "" -ForegroundColor White
    Write-Host "Please install Visual Studio Build Tools:" -ForegroundColor Yellow
    Write-Host "https://visualstudio.microsoft.com/downloads/" -ForegroundColor White
    Write-Host "Select 'Build Tools for Visual Studio 2022'" -ForegroundColor White
}

Write-Host "" -ForegroundColor White
Write-Host "📊 Setup verification complete!" -ForegroundColor Green
