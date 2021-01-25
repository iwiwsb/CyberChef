# Add file extensions to Crypto-Api imports
$file_list = Get-ChildItem ".\node_modules\crypto-api\src\" -Recurse -File
$file_list | ForEach-Object {
    (Get-Content $_.FullName) -replace '(from "\.[^"]*)(?<!\.mjs)";', '$1.mjs";' | Set-Content $_.FullName
}
