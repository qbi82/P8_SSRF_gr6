# Przekazanie ukończonej części technicznej

Zaimplementowano walidację i przypięcie IP w app/ssrf_policy.py, z publiczną funkcją
is_url_allowed() w app/app.py. Dopisano serwer przekierowań, legalny cel, dnsmasq,
kontrolowany rebinding i automatyczne testy. Nie wystarczyło zmienić samej funkcji logicznej:
bezpieczny transport musiał wykorzystać sprawdzony adres zamiast ponownie rozwiązywać DNS.

Wyniki: BEFORE 64 passed / 3 skipped; AFTER 67 passed; network 64 passed / 3 skipped.
Pełna instrukcja, ścieżki dowodów i ograniczenia: README.md oraz evidence/INDEX.json.
Raport zawiera wyniki rzeczywiste i poprawioną ocenę CVSS 8,6 dla ujawnienia danych.
Przed obroną obie osoby powinny przejść scenariusz OBRONA.md i rozumieć granice ochrony.
