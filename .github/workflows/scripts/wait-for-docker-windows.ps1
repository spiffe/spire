#!/usr/bin/env pwsh

Write-Host "Waiting for Docker to be ready..."

for ($i = 1; $i -le 60; $i++) {
    # Check if Docker is ready
    $output = docker info 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Docker is ready!"
        exit 0
    }

    # On first attempt, list and start Docker services
    if ($i -eq 1) {
        Write-Host "Docker not ready. Checking for Docker services..."
        $dockerServices = Get-Service | Where-Object { $_.Name -like '*docker*' -or $_.DisplayName -like '*docker*' }
        
        if ($dockerServices) {
            Write-Host "Available Docker services:"
            $dockerServices | Format-Table Name, Status, DisplayName -AutoSize
            
            # Start any stopped Docker services
            $dockerServices | Where-Object { $_.Status -ne 'Running' } | ForEach-Object {
                Write-Host "Starting service: $($_.Name)"
                Start-Service $_.Name -ErrorAction SilentlyContinue
            }
        } else {
            Write-Error "No Docker services found. Please ensure Docker is installed and configured correctly."
            exit 1
        }
    }

    # Show progress (detailed every 10 attempts)
    if ($i % 10 -eq 0) {
        Write-Host "Attempt $i/60 - Still waiting... Error: $output"
    } else {
        Write-Host "Attempt $i/60"
    }
    Start-Sleep -Seconds 2
}

Write-Error "Docker failed to start after 60 attempts"
exit 1
