# Zabezpieczenia sieciowe labu P8

Uruchom z katalogu głównego: `powershell -ExecutionPolicy Bypass -File .\run-evidence.ps1 -Scenario network`.
Nakładkę compose stosujemy łącznie z bazowym plikiem, nigdy samodzielnie.
Compose >= 2.24.4 obsługuje `!override`, które zastępuje listę sieci aplikacji.

Aplikacja jest odłączona od internal. Entry point wykonuje app/egress-rules.sh i dopiero
potem uruchamia proces jako UID 10001 bez capabilities. Kontener ma NET_ADMIN dla etapu
inicjalizacji; sam proces aplikacji już go nie ma. hardening/egress-rules.sh odsyła do
jedynej implementacji w app/, aby kopie nie rozchodziły się.

Przy podatnym kodzie T1, T2, T4, T5a/T5b są blokowane na poziomie połączenia (502), T7 działa (200),
a file:// nadal działa (200). Poprawka w kodzie jest potrzebna do ochrony plików lokalnych.
Wyjątki zapory i ograniczenia są opisane w głównym README. Dowody zawierają aktywne reguły
iptables i ip6tables; wyniki końcowe wskazuje evidence/latest-network.txt.
