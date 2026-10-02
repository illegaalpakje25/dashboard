# JDW Dashboard

Privé-dashboard voor jdw-content.nl, jdwtrackside.com en pm-tuning.nl. Met bereikbaarheid, SSL/DNS/sitegegevens, inloggeschiedenis, inhoudsdatums en handmatig deblokkeren voor PM Tuning.

## Vercel instellen

1. Importeer `illegaalpakje25/dashboard` in Vercel als nieuw project.
2. Framework: **Other**. Root Directory: **./**. Laat de instellingen uit `vercel.json` staan. Node.js 22.
3. Voeg onderstaande Environment Variables toe voor Production en, als je previews gebruikt, ook Preview. De waarden staan in het afzonderlijke lokale bestand `PRIVATE-vercel-setup.txt`; upload dit bestand nooit naar GitHub.
   - `PM_MONITOR_TOKEN`: leessleutel van de PM Tuning-monitor.
   - `PM_MONITOR_ACTION_TOKEN`: afzonderlijke deblokkeersleutel.
4. Klik Deploy. De browser vraagt om gebruikersnaam **admin** en de afgesproken pincode in het wachtwoordveld. Er is geen DASHBOARD_PASSWORD_SHA256-variabele meer nodig.

De toegang gebruikt de door de eigenaar gekozen vaste pincode. Dit is een eenvoudige toegangsrem, geen sterke beveiliging: een korte pincode is makkelijk te raden. Alle pagina's, bestanden en API-routes vereisen HTTP Basic-authenticatie. Vercel gebruikt HTTPS. Gebruik lokaal alleen localhost. Sluit de privésessie van je browser om opgeslagen Basic-authenticatie te wissen. Een bestaande DASHBOARD_PASSWORD_SHA256-variabele wordt niet meer gebruikt.

## Controle-interval en historie

Zolang het dashboard geopend is, vraagt het elke 3 seconden de status op. De server hergebruikt metingen maximaal 60 seconden. De klok telt af naar de volgende controle. Een koude start of andere serverinstantie kan een nieuwe meting starten. Dit is geen 24/7-monitor zonder geopende pagina.

Vercel heeft geen permanente lokale schijf: de bereikbaarheidshistorie is tijdelijk, per serverinstantie, maximaal 24 uur. De PM Tuning-inloggeschiedenis en deblokkeringen worden wel duurzaam bij PM Tuning bewaard. Er worden nooit wachtwoorden van inlogpogingen opgeslagen. Een locatie is een schatting op basis van het IP.

## Lokaal

Kopieer `.env.example` naar `.env`, vul de waarden in en gebruik `npm start`. Open http://127.0.0.1:3001. `npm test` controleert authenticatie, gesloten standaardinstelling, afscherming van bestanden en bescherming van deblokkeeracties.

De UI zit in `assets.mjs`, de monitor in `monitor.mjs`, en alle routes lopen via `api/index.mjs` en `handler.mjs`. Er zijn geen externe npm-dependencies.
