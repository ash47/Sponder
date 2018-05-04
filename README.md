# Sponder
Sponder -- Self Responder -- Steal your own NetNTLMv2 hash on Windows

## What does this do?
 - Retrieves the NetNTLMv2 hash of the user that runs the executable, outputs it to the console, and then closes.
 - I would recommend you run this via `cmd.exe` otherwise you won't see the hash.

## What's a NetNTLMv2 Hash?
 - It's a NTLM challenge response hash.
 - It can be cracked to retreive the password that was used to produce the response.
 - You can crack it with HashCat as follows: `hashcat64.exe -m 5600 -a 0 <fileWithHash.txt> <wordlist.txt>`

## How doe it work?
 - It spins up a HTTP server on the first available port.
 - It creates a web request, and instructs the computer to send the user's credentials if it needs auth.
 - The HTTP server requests NTLM auth.
 - The client authenticates.
 - The server captures the challenge / response and outputs a crackable hash.
 - The application closes.

## How do I use it?
 - Download a copy from the [releases section](https://github.com/ash47/Sponder/releases)
 - Launch `cmd.exe`, and then execute the program -- the hash will be outputed to the console.
