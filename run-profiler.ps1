param(
	[Parameter(ValueFromRemainingArguments = $true)]
	[string[]]$QueryArgs
)

if (-not $QueryArgs -or $QueryArgs.Count -eq 0) {
	$QueryArgs = @("plan", "list")
}

$profiler = Get-Command teamy-profiler -ErrorAction SilentlyContinue
if (-not $profiler) {
	throw "teamy-profiler not found in PATH"
}

& $profiler.Source run cargo `
	--project $PSScriptRoot `
	--bin teamy-mover `
	--profile release `
	--feature extended_observability `
	--feature tracy `
	-- @QueryArgs
exit $LASTEXITCODE
