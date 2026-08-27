# Panel urządzeń sieciowych

Lokalna aplikacja webowa do ewidencji i monitorowania urządzeń sieciowych na hali
produkcyjnej (terminale, drukarki etykiet, wagi Bizerba, komputery). Bez bazy danych,
bez zależności zewnętrznych do zainstalowania — tylko Python (biblioteka standardowa)
+ statyczny HTML/JS.

## Funkcje

- Ewidencja urządzeń: nazwa, IP, lokacja, typ, notatki, słowa kluczowe
- Automatyczne rozpoznawanie typu/zakładu/numeru z nazwy urządzenia (np. `T104-0192`)
- Wyszukiwanie, filtrowanie, sortowanie, stronicowanie
- Ping urządzeń (pojedynczo lub widoczne naraz, równolegle), z opcjonalnym auto-pingiem w tle
- Tunel SSH → VNC dla terminali (jednym kliknięciem otwiera SSH w nowym oknie konsoli)
- Tryb jasny / ciemny
- Hasło administracyjne wymagane do zapisu (przechowywane wyłącznie jako hash PBKDF2-SHA256)
- Ochrona przed nadpisaniem cudzych zmian przy równoczesnej edycji
- Automatyczne kopie zapasowe danych przy każdym starcie programu
- Log zmian (kto/kiedy/co) w pliku tekstowym

Pełny opis wszystkich funkcji, endpointów API i mechanizmów bezpieczeństwa:
zobacz `Dokumentacja_Panel_Urzadzen.docx` (jeśli dołączona do repo) lub poniższe sekcje.

## Wymagania

- Python 3 (zaznacz „Add Python to PATH" przy instalacji z [python.org](https://www.python.org/))
- Do funkcji tunelu SSH: zainstalowany klient OpenSSH (na Windows 10/11 to opcjonalna
  funkcja systemowa: *Ustawienia → Aplikacje → Opcjonalne funkcje → OpenSSH Client*)

## Instalacja i uruchomienie

```powershell
git clone <adres-tego-repo>
cd panel
python app.py
```

Przy pierwszym uruchomieniu program poprosi o ustawienie hasła administracyjnego
(dwukrotne wpisanie, ukryte). Hasło zostaje zapisane w postaci zahashowanej
w `admin_password.json` — **ten plik nie jest częścią repozytorium** (patrz `.gitignore`).

Otwórz w przeglądarce:

```
http://localhost:5000
```

Aby inni w sieci lokalnej mogli się podłączyć, wejdź pod adresem IP komputera,
na którym działa serwer, np. `http://192.168.1.10:5000`, i dopuść port 5000
w zaporze systemowej:

```powershell
New-NetFirewallRule -DisplayName "Panel urzadzen" -Direction Inbound -LocalPort 5000 -Protocol TCP -Action Allow
```

**Model pracy:** jedna osoba uruchamia `app.py` (pełni rolę serwera), wszyscy pozostali
łączą się przeglądarką pod jej adresem IP — nie potrzebują własnej kopii aplikacji.

## Zmiana hasła administracyjnego

```powershell
python app.py --set-password
```

## Konfiguracja

| Zmienna / flaga | Opis |
|---|---|
| `DEVICE_PANEL_DATA_DIR` | Folder, w którym trzymane są dane (domyślnie folder aplikacji). Pozwala wskazać np. dysk sieciowy. |
| `DEVICE_PANEL_PASSWORD` | Tylko przy migracji ze starszej wersji — jednorazowo hashowana do pliku przy pierwszym starcie. |
| `--set-password` | Zmienia zapisane hasło administracyjne. |

```powershell
$env:DEVICE_PANEL_DATA_DIR = "\\SERWER\Sciezka\Do\Danych"
python app.py
```

## Dane urządzeń

`devices.json` **nie jest częścią tego repozytorium** (patrz `.gitignore`) — zawiera
realne dane urządzeń zakładowych i nie powinien trafiać do publicznego repo.

Żeby uruchomić panel z własnymi danymi, skopiuj plik startowy i uzupełnij go:

```powershell
Copy-Item devices.example.json devices.json
```

Struktura pojedynczego urządzenia (pola opcjonalne, poza `name`):

```json
{
  "name": "T104-0192",
  "ip": "192.168.1.192",
  "type": "terminal",
  "area": "EXPORT",
  "addressMode": "dhcp",
  "keywords": ["terminal", "export"],
  "note": "Opis / lokalizacja"
}
```

## Struktura repozytorium

```
app.py               – backend (Python, http.server, bez zależności zewnętrznych)
index.html           – interfejs
static/app.js        – logika frontendu
static/style.css     – style (jasny/ciemny motyw)
devices.example.json – przykładowa struktura danych urządzeń (skopiuj do devices.json)
config.json          – obszary, typy, ustawienia tunelu SSH/VNC
install.txt          – skrócona instrukcja instalacji
```

Pliki generowane automatycznie w trakcie działania (**nieśledzone przez git**,
patrz `.gitignore`): `devices.json` (realne dane), `admin_password.json`, `changes.log`, `backups/`.

## Bezpieczeństwo — skrót

- Hasło: hash PBKDF2-HMAC-SHA256, 200 000 iteracji, losowa sól — nigdzie w postaci jawnej
- Zapis danych: atomowy (plik tymczasowy + podmiana), odporny na przerwanie w trakcie zapisu
- Ochrona przed jednoczesną edycją: wersjonowanie pliku (hash), konflikt = odrzucony zapis (HTTP 409)
- Log każdej zmiany (IP, czas, rodzaj akcji) w `changes.log`
- Aplikacja działa wyłącznie w sieci lokalnej, po zwykłym HTTP — nie wystawiać do internetu

## Licencja / użycie wewnętrzne

Narzędzie wewnętrzne zakładu — brak licencji open source, nie przeznaczone do
dystrybucji poza organizacją.
