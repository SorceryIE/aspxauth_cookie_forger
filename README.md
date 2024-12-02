# ASPXAUTH Cookie Forger
This is a CLI tool for decrypting and encrypting cookies from dotnet FormsAUthentication using machine keys.

This tool primarily relies on this library: https://github.com/dazinator/AspNetCore.LegacyAuthCookieCompat

To build: ```dotnet build```

Decrypt: ``` ./bin/Debug/net48/cookie_forger.exe --ekey XXX --vkey XXX --compatibility --data XXX```

Encrypt: ``` ./bin/Debug/net48/cookie_forger.exe --ekey XXX --vkey XXX --compatibility --name XXX --userData XXX``` 

