# Skrypt Synchronizacji Czasu Active Directory - Opis Opcji

## OPCJA 1: Sprawdz status synchronizacji czasu

Ta opcja sprawdza wszystkie kontrolery domeny i pokazuje ich aktualny czas, roznice wzgledem komputera lokalnego oraz zrodlo synchronizacji. Kazdy DC otrzymuje status OK (roznica mniejsza niz 30 sekund), OSTRZEZENIE (30-60 sekund) lub KRYTYCZNY (ponad 60 sekund). To pierwsza opcja ktorej uzywasz przy diagnozowaniu problemow - uruchamiaj ja regularnie, np. raz w tygodniu, zeby upewnic sie ze wszystko dziala prawidlowo. Jesli zobaczysz status KRYTYCZNY lub OSTRZEZENIE, to znak ze trzeba podjac dzialania naprawcze.

## OPCJA 2: Skonfiguruj zrodlo czasu PDC

Konfiguruje kontroler PDC Emulator jako glowne zrodlo czasu dla calej domeny. PDC synchronizuje sie z zewnetrznymi serwerami NTP (domyslnie polskie serwery pool.ntp.org oraz time.windows.com), a wszystkie pozostale kontrolery domeny synchronizuja sie z PDC. Uzyj tej opcji podczas poczatkowej konfiguracji nowej domeny, po reinstalacji PDC, lub gdy chcesz zmienic zrodla czasu NTP. Pamietaj ze PDC musi miec dostep do Internetu, zeby polaczyc sie z serwerami NTP.

## OPCJA 3: Zresetuj konfiguracje czasu DC

Resetuje i rekonfiguruje usluge W32Time na wybranym kontrolerze domeny. Skrypt wyrejestruje i ponownie zarejestruje usluge, a nastepnie skonfiguruje ja zgodnie z rola serwera - PDC bedzie synchronizowal sie z zewnetrznymi NTP, a pozostale DC z hierarchia domeny. Uzyj tej opcji gdy konkretny kontroler domeny ma problemy z synchronizacja czasu, po awarii serwera, lub gdy zmieniales konfiguracje recznie i chcesz wrocic do ustawien domyslnych. To pierwsza opcja naprawcza do wyprobowania przy problemach z pojedynczym DC.

## OPCJA 4: Wymus synchronizacje calej domeny

Laczy sie ze wszystkimi kontrolerami domeny jednoczesnie i wymusza na kazdym natychmiastowa synchronizacje czasu. Uzyj tej opcji po wykonaniu zmian w konfiguracji czasu (np. po zmianie zrodel NTP na PDC), gdy widzisz roznice czasu miedzy kontrolerami, lub gdy chcesz szybko zsynchronizowac cala domene bez czekania na automatyczna synchronizacje. Ta opcja nie zmienia konfiguracji - tylko wymusza synchronizacje na bazie aktualnych ustawien.

## OPCJA 5: Uruchom tryb monitorowania

Uruchamia ciagly monitoring synchronizacji czasu ze automatycznym odswiezaniem co 30 sekund (lub inny ustawiony czas). Ekran wyswietla aktualny status wszystkich kontrolerow domeny z kolorowym oznaczeniem problemow. Uzyj tej opcji podczas wykonywania krytycznych zmian w infrastrukturze, gdy chcesz obserwowac jak zachowuje sie synchronizacja w czasie rzeczywistym, lub gdy podejrzewasz przerywawe problemy z czasem. Monitoring mozesz zatrzymac w kazdej chwili przez CTRL+C. Doskonale nadaje sie tez do prezentacji na ekranie w serwerowni.

## OPCJA 6: Testuj lacznosc NTP

Sprawdza czy kontrolery domeny maja dostep do zewnetrznych serwerow czasu NTP. Testuje kazdy serwer z listy (pool.ntp.org, time.windows.com, time.nist.gov) i pokazuje czy polaczenie dziala. Uzyj tej opcji gdy PDC ma status KRYTYCZNY i podejrzewasz problemy z dostepem do Internetu, po zmianach w konfiguracji zapory, lub gdy chcesz sprawdzic czy zewnetrzne serwery NTP sa dostepne. Jesli test pokazuje bledy, to znaczy ze PDC nie moze synchronizowac czasu z Internetem i cala domena bedzie miec problemy.

## OPCJA 7: Napraw usluge W32Time

To zaawansowana opcja naprawy uszkodzonej uslugi synchronizacji czasu. Mozesz naprawic usluge lokalnie, na wybranym kontrolerze, lub na wszystkich DC jednoczesnie. Proces naprawy zatrzymuje usluge, wyrejestrowuje ja, rejestruje ponownie, konfiguruje zgodnie z rola serwera i wymusza synchronizacje. Uzyj tej opcji gdy usluga W32Time jest zatrzymana i nie da sie jej uruchomic, gdy resetowanie przez opcje 3 nie pomoglo, gdy widzisz bledy krytyczne w dzienniku zdarzen zwiazane z W32Time, lub po powaznnejszej awarii serwera. To opcja ostatniej szansy przed reinstalacja systemu.

## OPCJA 8: Skonfiguruj czlonka domeny

Konfiguruje synchronizacje czasu na stacjach roboczych i serwerach czlonkowskich domeny (nie-kontrolerach). Mozesz skonfigurowac komputer lokalny, zdalny komputer, lub wiele komputerow z listy. Dodatkowo mozesz przetestowac lacznosc czasowa z kontrolerami domeny. Uzyj tej opcji gdy nowe komputery w domenie maja zly czas, gdy stacje robocze pokazuja inne godziny niz serwery, po dolaczeniu komputera do domeny, lub gdy komputer byl dlugo wylaczony i jego zegar sie rozjjechal. Konfiguracja ustawia synchronizacje z hierarchia domeny, wiec komputery beda automatycznie synchronizowac sie z najblizszym kontrolerem.

---

## Kiedy uzywac ktorej opcji - Scenariusze

### Regularna konserwacja
Raz w tygodniu uruchom opcje 1 zeby sprawdzic czy wszystko dziala. Jesli wszystko OK, nie rob nic wiecej.

### Nowa domena lub migracja
Uruchom kolejno opcje 2, 4, 1 - skonfigurujesz PDC, wymuszysz synchronizacje i sprawdzisz wyniki.

### Problem z jednym kontrolerem
Uruchom opcje 1 zeby zidentyfikowac problematyczny DC, potem opcje 3 na tym DC, a jesli nie pomoze to opcje 7-2.

### Masowe problemy z cala domena
Uruchom opcje 6 zeby sprawdzic dostep do NTP, potem opcje 7-3 zeby naprawic wszystkie DC, nastepnie opcje 2 i 4 zeby przekonfigurowac i zsynchronizowac.

### Problemy ze stacjami roboczymi
Uruchom opcje 8-4 zeby sprawdzic lacznosc, potem opcje 8-1 lub 8-2 zeby skonfigurowac komputery.

### Po zmianach w infrastrukturze
Uzyj opcji 5 zeby monitorowac synchronizacje w czasie rzeczywistym podczas wprowadzania zmian.
