# P8 SSRF i granica zaufania chmury

Laboratorium do przedmiotu Bezpieczeństwo aplikacji internetowych, Akademia WSB, 2026.
Autorzy: Jakub Tadewicz i Adam Basoń. Dane są fikcyjne, a testy dotyczą wyłącznie własnych kontenerów.

## Uruchomienie

Wymagany Docker Desktop lub Docker Engine z Compose co najmniej 2.24.4.
Pierwsza budowa pobiera obrazy i pakiety. Same testy nie kontaktują się z Internetem.

```powershell
docker compose up --build
```

Aplikacja jest dostępna tylko lokalnie: http://127.0.0.1:8080/health.
Domyślny tryb to `hardened` (`VULNERABLE=0`). Legalny cel testowy: `http://cdn.test/`.
Pobieramy go przez aplikację, nie bezpośrednio z hosta:

```powershell
curl.exe -G --data-urlencode "url=http://cdn.test/" http://127.0.0.1:8080/fetch
```

Sieć `public` jest standardowym mostem Docker z NAT, potrzebnym do publikacji portu na localhost.
Sieć `internal` ma `internal: true`. Zakres 93.184.216.0/24 to symulowane publiczne IP
**wewnątrz Docker labu**. Zestaw testów używa wyłącznie własnych usług i lokalnego DNS;
nie wysyłamy testów do publicznych właścicieli tych adresów. Usługi wewnętrzne nie publikują portów hosta.
Wariant `network` dodatkowo blokuje wyjście aplikacji poza dozwolone cele zaporą.

## Testy i dowody

PowerShell zbiera komplet dowodów bez lokalnej instalacji Pythona. Zatrzymaj poprzedni
pierwszoplanowy `compose up` przez Ctrl+C; skrypt uruchomi właściwy wariant w tle.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\run-evidence.ps1 -Scenario vulnerable
powershell -NoProfile -ExecutionPolicy Bypass -File .\run-evidence.ps1 -Scenario hardened -NoBuild
powershell -NoProfile -ExecutionPolicy Bypass -File .\run-evidence.ps1 -Scenario network -NoBuild
```

`-NoBuild` oznacza użycie wcześniej zbudowanych obrazów. Po zmianie kodu pomiń tę opcję.
Sam `run-evidence.ps1` bez parametru wykrywa tryb już uruchomionego labu.
Zmienne w bazowym compose są interpolowane: `$env:VULNERABLE='1'` włącza podatną wersję,
a `$env:VULNERABLE='0'` poprawkę. Skrypt ustawia je sam we własnym procesie.

Każdy przebieg zapisuje nowy katalog `evidence/<tryb>/<czas-UTC>-<identyfikator>/`:

- `T*.txt`, `L*.txt`: rzeczywisty URL żądania, status, nagłówki i treść;
- `T5b-dns-history.json`: rzeczywiste odpowiedzi DNS;
- `pytest.txt`, `pytest.xml`: wynik kompletnego zestawu testów;
- logi aplikacji, DNS, rebindingu i celów;
- `compose-resolved.yml`, `containers.txt`, `manifest.json`, `SHA256SUMS.json`;
- w trybie network także aktywne reguły IPv4 i IPv6.

Wskaźniki `evidence/latest-*.txt` i `evidence/INDEX.json` wskazują końcowe przebiegi.
Stare pliki z 10 października zachowano; T6a/T6b dotyczą wcześniejszego etapu i nie są
wynikami końcowego zestawu. Plansze PNG w `evidence/figures/` są czytelnymi wyciągami
z zapisów HTTP, a nie zrzutami interfejsu curl/Burp.
Rzeczywiste zrzuty przeglądarki znajdują się w `evidence/screenshots/`: BEFORE T1/T2/T6,
AFTER T1/T4/T5b/T6/T7 oraz widoki /health potwierdzające tryb.

### Końcowe wyniki

| Test | BEFORE | AFTER kod | Sieć przy podatnym kodzie |
|---|---:|---:|---:|
| T1 wewnętrzne /admin | 200, sekret | 403 | 502 |
| T2 metadane | 200, token fikcyjny | 403 | 502 |
| T3 127.1 | 502, próba połączenia | 403 | 502 |
| T4 przekierowanie 302 | 200, sekret | 403 | 502 |
| T5a nazwa z prywatnym IP | 200, sekret | 403 | 502 |
| T5b rzeczywista zmiana DNS | 200, sekret | 403 | 502 |
| T6 file:///etc/passwd | 200, plik | 403 | 200, plik |
| T7 legalny zasób | 200 | 200 | 200 |

AFTER: **67 passed** (55 jednostkowych i 12 integracyjnych).
BEFORE i network: **64 passed, 3 skipped**; pomijane są wyłącznie trzy testy limitów
zabezpieczonego kodu. Limity AFTER: za duża odpowiedź 413, timeout 504, pętla przekierowań 403.

T3 BEFORE nie daje 200, bo na loopback:80 nie ma usługi. Historyczny T7 miał 502 z powodu
brakującej usługi; obecnie legalna usługa działa na tej samej topologii przed i po poprawce.

## Architektura i implementacja

- `app/`: Flask i `is_url_allowed()`; moduł `ssrf_policy.py` realizuje walidację i bezpieczny transport;
- `internal-api/`: chroniony cel z fikcyjnym sekretem;
- `metadata-mock/`: fikcyjne metadane 169.254.169.254;
- `lab/fixture.py`: legalny cel oraz serwer przekierowań;
- `lab/dns/`: dnsmasq bez cache, bez zewnętrznych resolverów;
- `lab/rebinder.py`: lokalny DNS z TTL 0, pierwsza odpowiedź publiczna, następna prywatna;
- `tests/`: testy polityki oraz integracyjne T1–T7 i limity;
- `hardening/`: nakładka izolująca sieć i aktywująca zaporę;
- `OBRONA.md`: plan wystąpienia, demo i odpowiedzi na pytania.

Transport łączy się ze sprawdzonym IP, zachowując HTTP Host oraz TLS SNI i weryfikację
certyfikatu. Sprawdzenie nazwy, a następnie zwykłe `requests.get(url)`, nie zapobiega
rebindingowi. Każdy skok przekierowania jest ponownie walidowany.
ALLOWED_HOSTS zawiera także `private.test` i `rebind.test` celowo: testujemy kontrolę IP
również wtedy, gdy sama nazwa jest dopuszczona. W realnej aplikacji dopuszcza się tylko
niezbędne, kontrolowane cele.

## Warstwa sieciowa

Skrypt `-Scenario network` używa obu plików compose. Ręczny odpowiednik:

```powershell
$env:VULNERABLE='1'
docker compose -f docker-compose.yml -f hardening/docker-compose.hardened.yml up --build
```

To wariant demonstracyjny: kod pozostaje podatny, a blokadę zapewniają topologia i zapora.
Wyjątki zapory to resolver Dockera 127.0.0.11 (port docelowy jest zmieniany przez Docker),
DNS labu, lokalny healthcheck 127.0.0.1:8080 oraz fixture:80/443. Pozostały ruch jest
odrzucany, także dla IPv6. Reguły zakłada entrypoint; proces aplikacji działa jako UID 10001
bez capabilities. Zapora nie chroni odczytu pliku ani endpointu lokalnego healthcheck.

## Ograniczenia i odniesienia

To lab, nie wdrożenie produkcyjne. Serwer Flask jest serwerem developerskim. IPv6 i ustawienia
TLS są sprawdzane jednostkowo, bez pełnego testu TLS/IPv6 w topologii Docker. Budżet 10 s
jest sprawdzany między operacjami, a pojedynczy odczyt ma timeout 3 s. Polityka egress jest
dostosowana do stałych IP labu. Mapowanie do ASVS nie oznacza pełnej certyfikacji zgodności.

- [OWASP Top 10:2025 A01](https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/)
- [ASVS 5.0.0 V1.3.6](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x10-V1-Encoding-and-Sanitization.md)
- [WSTG 4.2 INPV-19](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery/)
- [SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [CVSS 3.1](https://www.first.org/cvss/v3.1/specification-document)

CVSS dla wykazanego ujawnienia: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` = 8,6,
przy założeniu odrębnej granicy uprawnień. Przy S:U wynik 7,5. Nie wykazano I:L.

## Zatrzymanie

```powershell
docker compose down
```

Dowody w katalogu projektu pozostają. Polecenie nie usuwa innych projektów Dockera.
