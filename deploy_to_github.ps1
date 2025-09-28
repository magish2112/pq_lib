# Symbios Network - GitHub Deployment Script
# Run this script to deploy the project to GitHub

param(
    [Parameter(Mandatory=$true)]
    [string]$GitHubUsername,

    [Parameter(Mandatory=$true)]
    [string]$RepositoryName = "symbios-network",

    [Parameter(Mandatory=$false)]
    [string]$Description = "🚀 Revolutionary blockchain platform solving the trilemma through symbiotic architecture"
)

Write-Host "🚀 Symbios Network - GitHub Deployment" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan

# Check if git is available
try {
    $gitVersion = git --version
    Write-Host "✅ Git found: $gitVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Git not found. Please install Git first." -ForegroundColor Red
    exit 1
}

# Check current git status
Write-Host "`n📊 Checking git status..." -ForegroundColor Yellow
git status --short

# Create GitHub repository using GitHub CLI (if available)
Write-Host "`n🔧 Attempting to create GitHub repository..." -ForegroundColor Yellow

try {
    # Try using GitHub CLI
    gh repo create $RepositoryName --public --description $Description --confirm
    Write-Host "✅ Repository created using GitHub CLI" -ForegroundColor Green
} catch {
    Write-Host "⚠️  GitHub CLI not found or failed. Please create repository manually:" -ForegroundColor Yellow
    Write-Host "   1. Go to https://github.com/new" -ForegroundColor White
    Write-Host "   2. Repository name: $RepositoryName" -ForegroundColor White
    Write-Host "   3. Description: $Description" -ForegroundColor White
    Write-Host "   4. Make it Public" -ForegroundColor White
    Write-Host "   5. Don't initialize with README, .gitignore, or license" -ForegroundColor White
    Write-Host "   6. Press 'Create repository'" -ForegroundColor White
    Write-Host ""
    Read-Host "Press Enter after creating the repository on GitHub"
}

# Add remote origin
$remoteUrl = "https://github.com/$GitHubUsername/$RepositoryName.git"
Write-Host "`n🔗 Adding remote origin: $remoteUrl" -ForegroundColor Yellow

try {
    git remote add origin $remoteUrl
    Write-Host "✅ Remote origin added" -ForegroundColor Green
} catch {
    Write-Host "⚠️  Remote origin might already exist. Trying to set URL..." -ForegroundColor Yellow
    git remote set-url origin $remoteUrl
    Write-Host "✅ Remote origin updated" -ForegroundColor Green
}

# Push to GitHub
Write-Host "`n📤 Pushing to GitHub..." -ForegroundColor Yellow
try {
    git push -u origin master
    Write-Host "✅ Successfully pushed to GitHub!" -ForegroundColor Green
} catch {
    Write-Host "❌ Push failed. Please check your credentials and try again." -ForegroundColor Red
    Write-Host "   You might need to:" -ForegroundColor Yellow
    Write-Host "   1. Set up SSH keys or personal access token" -ForegroundColor White
    Write-Host "   2. Configure git credentials: git config --global user.name 'Your Name'" -ForegroundColor White
    Write-Host "   3. Configure git credentials: git config --global user.email 'your.email@example.com'" -ForegroundColor White
    exit 1
}

# Verify deployment
Write-Host "`n🔍 Verifying deployment..." -ForegroundColor Yellow
try {
    $remoteInfo = git remote -v
    Write-Host "✅ Repository successfully deployed to GitHub!" -ForegroundColor Green
    Write-Host "   Repository URL: https://github.com/$GitHubUsername/$RepositoryName" -ForegroundColor Cyan
    Write-Host "   Remote info:" -ForegroundColor White
    Write-Host $remoteInfo -ForegroundColor Gray
} catch {
    Write-Host "⚠️  Could not verify deployment" -ForegroundColor Yellow
}

Write-Host "`n🎉 Deployment completed!" -ForegroundColor Green
Write-Host "   You can now work with this repository from any computer." -ForegroundColor Cyan
Write-Host "   Clone it with: git clone https://github.com/$GitHubUsername/$RepositoryName.git" -ForegroundColor White
