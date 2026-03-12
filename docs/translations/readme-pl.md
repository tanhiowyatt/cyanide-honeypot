[![Stars](https://img.shields.io/github/stars/tanhiowyatt/cyanide?style=flat&logo=GitHub&color=yellow)](https://github.com/tanhiowyatt/cyanide/stargazers)
[![CI](https://github.com/tanhiowyatt/cyanide/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/tanhiowyatt/cyanide/actions/workflows/ci.yml)
[![Security Scan](https://github.com/tanhiowyatt/cyanide/actions/workflows/security_scan.yml/badge.svg)](https://github.com/tanhiowyatt/cyanide/actions/workflows/security_scan.yml)

<p align="center">
  <img src="../../assets/branding/name.png" alt="Cyanide" width="500" height="auto">
</p>

# Cyanide – Honeypot SSH i Telnet o średnim poziomie interakcji

**Cyanide** to honeypot SSH i Telnet o średnim poziomie interakcji (medium-interaction), zaprojektowany w celu zmylenia atakujących i dogłębnej analizy ich zachowań. Łączy w sobie realistyczną emulację systemu plików Linux, zaawansowaną symulację komend (z obsługą potoków i przekierowań), solidne mechanizmy zapobiegające wykryciu oraz hybrydowy silnik ML do wykrywania anomalii.

---

### Funkcje

#### 1) Machine Learning do automatycznej klasyfikacji ataków i ekstrakcji IOC
- System automatycznie kategoryzuje aktywność sieciową na typy ataków (brute-force, credential stuffing, rekonesans, próby eksploitacji) na podstawie zachowania sesji i charakterystyki ładunku (payload).
- Zdarzenia są normalizowane wraz z ekstracją wskaźników kompromitacji (IOC), w tym adresów IP, portów, danych uwierzytelniających, user-agentów/banerów, komend, adresów URL, haszy artefaktów i słowników częstotliwości ataków.
- Generowane jest podsumowanie sesji, szczegółowo opisujące zamiary ataku, odchylenia od norm bazowych oraz zalecane IOC do blokowania lub integracji z regułami wykrywania.

#### 2) Zwiększony realizm w celu uniknięcia wykrycia honeypota
- Realistyczne czasy odpowiedzi i ich zmienność (błędy, opóźnienia, formaty komunikatów) zwiększają wskaźnik błędnej klasyfikacji przez automatyczne detektory honeypotów.
- Dynamiczne profile środowiska: banery usług, wersje i scenariusze operacyjne rozwijają się naturalnie, unikając statycznych szablonów.
- Zachowanie interfejsu imitujące człowieka: wiarygodne ograniczenia, komunikaty o błędach i drobne niespójności charakterystyczne dla systemów produkcyjnych.

#### 3) Zaawansowane integracje SOC i analityczne
- Strukturalne logi JSON ze ustandaryzowanym schematem zdarzeń ułatwiającym korelację i wyszukiwanie.
- Eksport zdarzeń do systemów zewnętrznych: stosy SIEM/logów (ELK/Splunk), powiadomienia webhook (Slack/Discord/Telegram) w czasie rzeczywistym.
- Konfigurowalne triggery i reguły dla alertów o krytycznych wzorcach (np. anomalna prędkość brute-force, przesyłanie dropperów, podejrzane komendy/ładunki).

---

### Szybki start

```bash
1. Uruchom środowisko
docker-compose up -d

2. Połącz się przez SSH
ssh root@localhost -p 2222

Z lokalnymi zmianami
docker-compose up -d --build
```

---

### Jak działa honeypot

Honeypot Cyanide wdraża **usługę-pułapkę** (decoy service) i prowadzi atakujących przez **kontrolowany scenariusz**: emuluje realistyczną usługę bez przyznawania rzeczywistego dostępu do hosta.

#### Profile YAML (Podstawa zachowania)
Zachowanie usługi jest definiowane za pomocą **profili YAML**:
- Emulowane funkcje (banery/wersje, błędy, ograniczenia);
- Logika odpowiedzi (reguły/szablony, rozgałęzianie);
- Stan sesji (uwierzytelnianie, kontekst, liczniki);
- Czynniki realizmu (opóźnienia/jitter, randomizacja).

#### MsgPack (Szybki czas wykonywania)
YAML służy jako „kod źródłowy”, kompilowany/buforowany do formatu **MsgPack** na potrzeby produkcyjne:
- Szybsze ładowanie/dekodowanie niż YAML/JSON;
- Mniejszy rozmiar, łatwiejsze buforowanie/dystrybucja;
- Stabilniejsza wydajność przy wysokim obciążeniu.

#### Przepływ sesji
1. Przychodzące zdarzenie (logowanie/komenda/ładunek)
2. Aktualizacja stanu
3. Zastosowanie reguł profilu (YAML/MsgPack)
4. Generowanie odpowiedzi (z realistycznym czasem)
5. Logowanie + ekstrakcja IOC

#### Logi i IOC
Przechwytywane są strukturalne zdarzenia: IP/ID sesji, próby logowania, komendy/ładunki, czasy i wyniki. Na tej podstawie ekstrahowane są **IOC**, klasyfikowane ataki, a alerty eksportowane do systemów SOC.

---

### Twórcy

Ten honeypot został stworzony przez **tanhiowyatt** i **Koshanzova Nikolaya**, założycieli Cyanide Labs. Nasza początkowa współpraca nad zaawansowanymi prototypami honeypotów przekształciła się w obecny zestaw narzędzi cyberbezpieczeństwa open-source, koncentrujący się na realistycznej symulacji zagrożeń, klasyfikacji ataków opartej na ML i bezproblemowej integracji z SOC.

---

### Ostrzeżenie

To oprogramowanie służy wyłącznie do celów edukacyjnych i badawczych. Uruchamianie honeypota wiąże się ze znacznym ryzykiem. Autor nie ponosi odpowiedzialności za jakiekolwiek szkody lub niewłaściwe użycie.
