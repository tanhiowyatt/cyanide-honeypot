# Cyanide Honeypot 2.1 🛡️

**Cyanide** to honeypot SSH i Telnet o wysokiej interakcji, zaprojektowany do zwodzenia i analizowania zachowań atakujących. Łączy w sobie realistyczną emulację systemu plików Linux, zaawansowaną symulację komend oraz głębokie mechanizmy zapobiegające wykryciu.

---

### 🌐 Tłumaczenia / Translations / Переводы
*   🇺🇸 [English (Angielski)](README.md)
*   🇷🇺 [Russian (Rosyjski)](README.RU.md)

---

## 🌟 Główne Funkcje

### 🧠 Realistyczna Emulacja
*   **Wieloprotokołowość**: Jednoczesna obsługa SSH (przez `asyncssh`) i Telnet na różnych portach.
*   **Dynamiczny System Plików**: W pełni funkcjonalny system plików Linux. Zmiany (tworzenie plików, usuwanie) persistują przez całą sesję.
*   **Zaawansowany Shell**: Obsługa potoków (`|`), przekierowań (`>`, `>>`) oraz łączenia poleceń (`&&`, `||`, `;`).
*   **Anti-Fingerprinting**: 
    *   **Network Jitter**: Losowe opóźnienia odpowiedzi (50-300ms) w celu symulacji realnej sieci.
    *   **Profile Systemowe**: Maskowanie jako **Ubuntu**, **Debian** lub **CentOS** (banery, `uname`, `/proc/version`).

### 📊 Informatyka Śledcza i Logowanie
*   **Nagrywanie TTY**: Rejestracja sesji w formacie kompatybilnym z `scriptreplay`.
*   **Strukturalny JSON**: Szczegółowe logi zdarzeń w formacie JSON dla integracji z ELK/Splunk.
*   **Biometria Klawiatury**: Analiza rytmu pisania w celu odróżnienia botów od ludzi.
*   **Kwarantanna**: Automatyczna izolacja plików pobranych przez `wget`, `curl`, `scp` lub `sftp`.
*   **VirusTotal**: Automatyczne skanowanie podejrzanych plików w kwarantannie.

---

## 🏗️ Architektura i Struktura

Projekt zbudowany jest na zasadzie modułowej z wykorzystaniem nowoczesnych wzorców Pythona:
*   **Wzorzec Fasada**: Główne funkcje są dostępne bezpośrednio z korzeni pakietów (np. `from core import HoneypotServer`).
*   **Rejestr Komend**: Dynamiczne ładowanie emulowanych komend poprzez centralny rejestr w `src/commands`.

### Struktura Katalogów
| Ścieżka | Opis |
|---------|-------------|
| `bin/` | Narzędzia do zarządzania i kontroli |
| `etc/` | Pliki konfiguracyjne (`cyanide.cfg`) |
| `src/core/` | Rdzeń serwera, emulator shella i logika systemu plików |
| `src/commands/` | Implementacje emulowanych komend Linux |
| `src/cyanide/` | Biblioteki pomocnicze i logowanie |
| `var/log/cyanide/` | Logi JSON i nagrania TTY |
| `var/quarantine/` | Odizolowane pliki |

---

## 🚀 Wdrożenie i Obsługa

### 🐳 Opcja 1: Docker (Zalecane)
Najszybszy i najbezpieczniejszy sposób uruchomienia.

```bash
# Zbuduj i uruchom w tle
docker-compose up -d --build

# Podgląd logów serwera w czasie rzeczywistym
docker-compose logs -f

# Zatrzymaj
docker-compose down
```

### 🐍 Opcja 2: Uruchomienie Lokalne
Wymaga **Python 3.10+**.

```bash
# 1. Instalacja zależności
make install

# 2. Konfiguracja
# Edytuj etc/cyanide.cfg (porty, profil OS, hasła)

# 3. Uruchom przez skrypt kontrolny
./bin/cyanide start

# Sprawdź status
./bin/cyanide status

# Zatrzymaj
./bin/cyanide stop
```

---

## 🛠️ Materiały Narzędziowe (`bin/`)

| Narzędzie | Opis |
|-----------|-------------|
| `./bin/cyanide` | Główny skrypt zarządzający (start, stop, status, restart). |
| `./bin/cyanide-replay` | Odtwarzacz logów TTY. |
| `./bin/cyanide-createfs` | Tworzy nowy "migawka" systemu plików z realnego katalogu. |
| `./bin/cyanide-clean` | Narzędzie do czyszczenia starych logów i plików w kwarantannie. |
| `./bin/cyanide-fsctl` | Narzędzie do ręcznego zarządzania bazą danych `fs.pickle`. |

---

## ⌨️ Emulowane Komendy

Cyanide obsługuje ponad 25 standardowych komend Linux, w tym:
*   **Nawigacja**: `cd`, `ls`, `pwd`.
*   **Operacje na plikach**: `cat`, `touch`, `mkdir`, `rm`, `cp`, `mv`, `id`.
*   **Informacyjne**: `uname`, `ps`, `whoami`, `who`, `w`, `help`.
*   **Zaawansowane**: `sudo`, `export`, `echo`.
*   **Sieciowe**: `curl`, `ping`, `wget` (z plikami zapisanymi w kwarantannie).
*   **Edytory**: `vi`, `vim`, `nano` (symulacja).

---

## 🕵️ Analiza Sesji (Scriptreplay)

Wszystkie sesje są nagrywane w `var/log/cyanide/tty/`. Każda sesja ma własny folder z plikiem danych (`.log`) i plikiem czasu (`.timing`).

**Jak odtworzyć sesję:**
1.  Znajdź odpowiedni folder sesji w `var/log/cyanide/tty/`.
2.  Wykonaj polecenie:
```bash
scriptreplay --timing var/log/cyanide/tty/<dir>/<dir>.timing --typescript var/log/cyanide/tty/<dir>/<dir>.log
```

---

## 💾 Persystencja i Migawki (fs.pickle)

System plików Cyanide jest przechowywany w pliku `share/cyanide/fs.pickle`. Jest to binarny zrzut chroniony sygnaturą HMAC.

**Jak stworzyć własną migawkę:**
Jeśli chcesz, aby atakujący widział strukturę Twojego realnego serwera:
```bash
sudo ./bin/cyanide-createfs / --output share/cyanide/fs.pickle
```

---

## 🧹 Konserwacja

Po długim czasie pracy zaleca się wyczyszczenie logów:
```bash
# Usuń logi starsze niż 7 dni
make clean
# lub konkretnie:
./bin/cyanide-clean --days 7 --force
```

---

## ⚠️ Ostrzeżenie
To oprogramowanie służy **wyłącznie do celów edukacyjnych i badawczych**. Uruchamianie honeypota wiąże się z ryzykiem. Autor nie ponosi odpowiedzialności za jakiekolwiek szkody.
