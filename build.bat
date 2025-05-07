@echo off
echo Building ZTP CLI binaries...
go build -o ztp-client.exe ./cmd/ztp-client
go build -o ztp-server.exe ./cmd/ztp-server
echo Done.
