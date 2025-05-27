$projects = @("authservice", "jokeservice", "quoteservice", "gatewayservice")

foreach ($project in $projects) {
    Write-Host "Building image for $project..."
    Set-Location $project
    ./mvnw spring-boot:build-image
    Set-Location ..
}

Write-Host "ALL IMAGES BUILT!"
