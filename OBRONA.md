# Prezentacja i demo na 10–12 minut

## Przebieg

1. **0:00–1:00, oboje:** temat P8, co chronimy i cel projektu. SSRF oznacza, że użytkownik steruje połączeniem wykonywanym przez serwer.
2. **1:00–3:00, Jakub:** diagram, dwie strefy, po co wewnętrzna usługa i fikcyjne metadane. Bezpośredni brak dostępu z hosta nie przeszkadza aplikacji podatnej w pobraniu danych.
3. **3:00–5:00, Jakub:** BEFORE T1/T2/T6 i skutki widoczne w zapisach HTTP. T3 jest próbą połączenia, ale nie wyciekiem, bo nie ma usługi na loopback:80.
4. **5:00–7:00, Adam:** walidacja schematu/hosta/portu/IP, wszystkie A/AAAA, przypięcie IP z zachowaniem Host/SNI, kontrola każdego przekierowania. Dlaczego samo sprawdzenie DNS nie wystarczy.
5. **7:00–9:30, Adam:** demo AFTER, 403 na atak i 200 na legalny cel. Pokaż 67 passed, historię dwóch odpowiedzi DNS oraz porównanie z BEFORE.
6. **9:30–10:30, Jakub:** niezależny wariant sieciowy blokuje T1/T2 przy podatnym kodzie; T6 nadal działa. Pokazuje to potrzebę ochrony w kodzie.
7. **10:30–12:00, oboje:** CVSS 8,6 z jawnym założeniem S:C, ograniczenia labu i wnioski; czas na krótkie pytania.

## Krótkie demo na żywo

Przed wystąpieniem upewnij się, że obrazy są zbudowane. Nie przeprowadzaj pierwszego pobierania pakietów podczas obrony.

```powershell
# BEFORE i zapis kompletnego przebiegu
powershell -ExecutionPolicy Bypass -File .\run-evidence.ps1 -Scenario vulnerable -NoBuild
curl.exe -G --data-urlencode "url=http://internal-api/admin" http://127.0.0.1:8080/fetch

# AFTER
powershell -ExecutionPolicy Bypass -File .\run-evidence.ps1 -Scenario hardened -NoBuild
curl.exe -G --data-urlencode "url=http://internal-api/admin" http://127.0.0.1:8080/fetch
curl.exe -G --data-urlencode "url=http://cdn.test/" http://127.0.0.1:8080/fetch
```

Oczekiwany obraz: BEFORE ujawnia fikcyjny sekret; AFTER odmawia z 403, a cel legalny zwraca SAFE_FIXTURE i 200.
Skrypt po każdym wariancie zapisze dokładne wyniki, więc nie trzeba kopiować tekstu z ekranu.
Scenariusz DNS jest deterministyczny w pytest: resetuje kontrolowany serwer przed dwoma pobraniami.
Nie klikaj go wcześniej ręcznie, bo zmienisz licznik odpowiedzi; ponowne uruchomienie testu wykona reset.

## Pytania, które warto umieć wyjaśnić

- **Czym SSRF różni się od zwykłego wejścia na adres?** Połączenie wykonuje serwer z własnym dostępem do sieci, nie komputer użytkownika.
- **Dlaczego nie wystarcza allowlista hostów?** Dozwolona nazwa może rozwiązać się na adres wewnętrzny; przekierowanie może zmienić cel.
- **Co daje przypięcie IP?** Łączymy się z dokładnie sprawdzonym adresem, więc klient nie pyta ponownie o nazwę po walidacji.
- **Jak dowiedliśmy rzeczywistego rebindingu?** Historia DNS pokazuje publiczny adres pierwszego zapytania i prywatny drugiego. Pierwsze pobranie ma legalną treść, drugie AFTER jest blokowane.
- **Dlaczego file:// działa w wersji podatnej?** To celowo dopisany błąd labu. requests samo nie wspiera tego schematu. Po poprawce odrzucamy go przed odczytem.
- **Czy 502 jest blokadą w kodzie?** Nie. AFTER polityka zwraca 403; 502 w wariancie sieciowym oznacza błąd połączenia. T3 BEFORE ma 502 z powodu braku usługi.
- **Po co T7?** Potwierdza brak regresji; sama odmowa wszystkiego nie jest poprawnym zabezpieczeniem funkcji.
- **Dlaczego CVSS 8,6, a nie 9,3?** Wykazaliśmy poufność, nie modyfikację danych. 9,3 wymagałoby I:L. S:C opiera się na założeniu odrębnej granicy uprawnień; dla S:U byłoby 7,5.
- **Czy to gotowa ochrona produkcyjna?** To sprawdzony lab. Wdrożenie wymaga m.in. serwera produkcyjnego, własnej polityki celów i egress, dalszej weryfikacji TLS/IPv6 oraz obsługi zmieniających się adresów usług.
