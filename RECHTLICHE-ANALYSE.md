# Rechtliche Risikoanalyse — Crelvo Portfolio & Markel Pro Media

**Erstellt:** 2026-06-11
**Anlass:** Absicherung gegen rechtlichen Ärger vor/während der Selbstständigkeit; Bewertung eines Versicherungsangebots (Markel Pro Media)
**Betreiber:** Konrad Reyhe (Crelvo), Kleinunternehmer §19 UStG, Wohnsitz Deutschland
**Impressum-Anschrift:** c/o MDC Management#6099, Welserstraße 3, 87463 Dietmannsried (PO/Management-Adresse, voller Klarname, nicht Privatadresse)
**Bisheriger Umsatz:** ~0 EUR (höchstens ~30 EUR von AbschlussCheck/BachelorCheck)

---

## ⚠️ WICHTIGER HINWEIS VORWEG — keine Rechtsberatung

Dieses Dokument ist **keine Rechtsberatung** und ich bin kein Rechtsanwalt. Es ist eine **technische Compliance-Analyse**: Ich habe alle deine öffentlich erreichbaren Websites systematisch auf die typischen deutschen Pflichten geprüft (Impressum/DDG, Datenschutz/DSGVO, Cookie-Recht/TDDDG, Werbekennzeichnung/UWG, Verbraucherrecht/BGB, Branchenrecht StBerG/RDG/HWG/GlüStV/WpHG) und die Befunde nach Risiko sortiert. Für eine verbindliche Bewertung — gerade bei den als „Hoch"/„Kritisch" markierten Punkten — solltest du das mit einem Anwalt (IT-Recht/Wettbewerbsrecht) oder bei den Steuer-Tools mit einem Steuerberater gegenchecken. Die gute Nachricht: Die meisten gefundenen Probleme sind **schnell und billig selbst behebbar**, bevor sie jemand abmahnt.

---

## 1. Executive Summary — die ehrliche Gesamtlage

Du machst dir zu Recht Gedanken, aber die Lage ist **beherrschbar**. Es gibt **keine Zeitbombe**, die dich ruiniert — aber es gibt eine Handvoll konkreter Punkte, die ein Abmahnanwalt oder die Wettbewerbszentrale heute sofort angreifen könnte. Fast alle sind in 1–2 Tagen behebbar.

**Das deutsche Abmahn-Risiko ist real, aber nicht dramatisch für dich, weil:**
- Du **fast keinen Umsatz** und **kaum Traffic auf den kommerziellen Seiten** hast → du bist (noch) kein lohnendes Abmahnziel. Abmahnungen kommen meist von Wettbewerbern oder spezialisierten Abmahnvereinen, die zuerst sichtbare/umsatzstarke Player treffen.
- Deine Datenschutz-Grundausstattung ist auf den meisten Seiten **besser als bei vielen Indie-Projekten** (selbstgehostetes, cookieloses Plausible — kein Cookie-Banner nötig).
- **Keine einzige Seite hat gefälschte Testimonials/Sternebewertungen** mit einer Ausnahme (BannerForge) — das ist eine deiner größten cross-project Risiken laut deiner eigenen Policy, und du bist da fast sauber.

**Die scharfen Kanten (Details unten):**
1. **Google Analytics ohne funktionierende Einwilligung** auf PromoForge, BannerForge, AbfindungsOptimizer, SchenkungsPlaner — TDDDG §25-Verstoß, und bei den zwei Steuer-Tools steht in der Datenschutzerklärung sogar wörtlich „keine Cookies / keine Datenerhebung", während GA läuft → **falsche Datenschutzerklärung** (zusätzlich UWG-relevant).
2. **BannerForge: TLS-Zertifikat abgelaufen** (~23. Mai 2026) → Seite inkl. Pflichtangaben für echte Besucher tot, PLUS drei **erfundene Testimonials** + „1.000+ marketers"-Behauptung.
3. **Komplett fehlende Impressen/Datenschutz** auf mehreren kommerziellen Seiten (codewithrigor.com, orbedge.de, betpilot, orb.crelvo.dev).
4. **orbedge.de**: Trading-EA-Verkaufsseite mit konkreten Backtest-Renditeversprechen (u. a. ein unrealistischer „Sharpe 17.43"), nur Mini-Disclaimer, kein Impressum → **höchstes Einzelrisiko** (Finanz-/Anlagewerbung, WpHG/UWG, und genau die Sparte, die deine geplante Versicherung NICHT abdeckt).
5. **Verbraucherrecht-Lücken** bei jeder zahlungspflichtigen Seite (Button-Lösung §312j, Widerrufsbelehrung + Digital-Content-Verzicht §356 Abs. 5 BGB, AGB, Preis inkl. MwSt).
6. **Kleinunternehmer-Widerspruch:** Mehrere Seiten werben „inkl. 19 % MwSt", obwohl du als §19-Kleinunternehmer keine USt ausweisen darfst.

---

## 2. Risiko-Heatmap (alle öffentlichen Sites)

| Site | Kategorie | Impressum | Datenschutz | Cookie/Tracking | Testimonials | Verbraucherrecht | Branchenrisiko | **Gesamt** |
|---|---|---|---|---|---|---|---|---|
| **orbedge.de** | Trading-EA Verkauf | ❌ fehlt | ❌ fehlt | GA? nein, Plausible | Backtest-Renditeclaims | n/a (Coming Soon) | WpHG/UWG **Anlage** | 🔴 **Kritisch** |
| **bannerforge.app** | SaaS bezahlt | ⚠️ tot (Cert) | ⚠️ tot (Cert) | GA o. Consent | 🔴 **3 Fake-Testimonials** | USD, keine MwSt | – | 🔴 **Kritisch** |
| **abfindungsoptimizer.de** | Steuer-Tool 9,99€ | ⚠️ §5 TMG veraltet | 🔴 **falsch** (GA verschwiegen) | GA o. Consent | sauber | Checkout aus → Lücken latent | StBerG-Grenze | 🟠 **Hoch** |
| **schenkungsplaner.eu** | Steuer-Tool 9,99€ | ⚠️ §5 TMG veraltet | 🔴 **falsch** (GA verschwiegen) | GA o. Consent | sauber | Checkout aus → Lücken latent | StBerG-Grenze | 🟠 **Hoch** |
| **promoforge.app** | SaaS bezahlt | ✅ (DDG) | ⚠️ GA nicht genannt | 🔴 GA feuert vor Consent | ✅ ehrlich leer | inkl-MwSt-Widerspruch | – | 🟠 **Hoch** |
| **abschlusscheck.de** | Tool bezahlt (Stripe) | ✅ | ⚠️ keine Art-6-Basis, US-Transfer | Stripe? prüfen | sauber | 🔴 Button „Jetzt prüfen", keine AGB/Widerruf | – | 🟠 **Hoch** |
| **codewithrigor.com** | Verkauf eBook/Programm | ❌ **fehlt** | ❌ **fehlt** | unklar | sauber | unklar | – | 🟠 **Hoch** |
| **betpilot.crelvo.dev** | Wett-Tool (login-gated) | ❌ fehlt (Login-Seite) | ❌ fehlt | kein Banner | n/a (gated) | n/a | GlüStV (versich.-ausgeschl.) | 🟠 **Hoch** |
| **agorahoch3.org** | Client-Projekt | ❌ fehlt | ❌ fehlt | – | sauber | – | DDG (Haftung Kunde) | 🟠 **Hoch (Kunde)** |
| **fiscanto.de** | Krypto-Steuer-Daten | ✅ (DDG) | ✅ gut | ✅ cookieless | sauber | B2B, kein Online-Checkout | ⚠️ StBerG-Grenze (gut entschärft) | 🟡 **Mittel** |
| **sacredlens.de** | Tool Abo bezahlt | ✅ (DDG/MStV) | ✅ gut | ✅ cookieless | sauber | 🔴 Button „Upgrade", AGB EN ohne Widerruf | – | 🟡 **Mittel** |
| **lohnpruefung.de** | Gratis-Tool + Affiliate | ✅ | ⚠️ Affiliate nicht genannt | ✅ cookieless | „Testsieger" unbelegt | gratis (kein Checkout) | ⚠️ Affiliate-Kennzeichnung | 🟡 **Mittel** |
| **theadhdmind.org** | Content (Gesundheit) | ✅ | 🔴 **404 (kaputt)** | – | sauber | n/a | HWG: „99%"-Claim, kein Disclaimer | 🟡 **Mittel** |
| **best-age.de** | Gratis-Rechner Sozial | ⚠️ unvollständig (nur „Leipzig") | ✅ gut | ✅ cookieless | sauber | gratis | RDG: Disclaimer im Impressum vorhanden | 🟡 **Mittel** |
| **orb.crelvo.dev** | Trading-Monitor (offen) | ❌ fehlt | ❌ fehlt | kein Tracking | sauber (Daten leer) | n/a | latent (Finanz) | 🟡 **Mittel** |
| **oldworldlogos.com** | Showcase/Game | ❌ fehlt | ❌ fehlt | unklar | sauber | – | – | 🟡 **Mittel** |
| **survivorai.app** | App-Landing (multi-lang) | ❌ fehlt | ❌ (sagt „no telemetry") | keine | sauber | n/a | Disclaimer gut | 🟡 **Mittel** |
| **christistrue.org** | Apologetik (Content) | ❌ fehlt | ❌ fehlt | keine | sauber | n/a | nicht-kommerziell | 🟢 Niedrig–Mittel |
| **thedesigninference.org** | Content | ❌ fehlt | ❌ fehlt | keine | sauber | n/a | nicht-kommerziell | 🟢 Niedrig–Mittel |
| **patternmusic.art** | Gratis-Toy | ⚠️ 500-Fehler | unklar | keine | sauber | n/a | – | 🟢 Niedrig–Mittel |
| **crelvo.dev** | Portfolio | ✅ | ✅ | ✅ kein Tracking | sauber | – | – | 🟢 **Niedrig** |
| **dreiraum.studio** | Studio | ✅ | ✅ | ✅ | sauber | – | – | 🟢 **Niedrig** |
| **dockfolio.dev** | Produkt-Marketing | ✅ (DDG, §19) | ✅ | ✅ cookieless | sauber | – | – | 🟢 **Niedrig** |
| **bewerbungsfotos-ai.de** | Headshot-AI bezahlt | ✅ (DDG, §19) | ✅ stark (Art. 9 Biometrie!) | ✅ Umami cookieless | sauber | ✅ Widerruf + §356-Verzicht vorhanden | – | 🟢 **Niedrig–Mittel** |

> **Headshot AI ist dein Musterschüler** — selbst die Biometrie-Datenverarbeitung ist korrekt auf Art. 9(2)(a) DSGVO gestützt, Widerrufsbelehrung mit Digital-Content-Verzicht vorhanden, cookieloses Umami. Nimm dessen Impressum/Datenschutz/Widerruf-Seiten als Vorlage für alle anderen bezahlten Seiten.

---

## 3. Die Querschnitts-Themen (gelten für mehrere Seiten)

### 3.1 Impressumspflicht (DDG §5) — was du brauchst
Seit 2024 heißt das Gesetz **DDG** (Digitale-Dienste-Gesetz), nicht mehr TMG. Pflichtangaben für geschäftsmäßige Seiten:
- **Voller Name** (hast du überall, wo Impressum existiert ✓ — du gibst korrekt deinen Klarnamen an, das ist Pflicht und richtig so)
- **Ladungsfähige Anschrift** — hier der wichtigste Dauerpunkt: deine `c/o MDC Management#6099`-Adresse ist eine **virtuelle Büro-/Postweiterleitungsadresse**. Das ist **zulässig**, *solange du dort tatsächlich für Zustellungen erreichbar bist* (d. h. Post wird zuverlässig weitergeleitet, du kannst dort verklagt/gemahnt werden). Reine „Briefkästen", an denen niemand erreichbar ist, wurden von Gerichten teils als **nicht ladungsfähig** verworfen. → **Kein Akutproblem, aber Klärungspunkt:** Stelle sicher, dass MDC dir Schriftstücke tatsächlich zustellt. Du gibst zu Recht NICHT deine Privatadresse an — das musst du als Einzelunternehmer aber abwägen (s. 3.7).
- **Schnelle elektronische Kontaktaufnahme** — E-Mail reicht rechtlich. Eine zweite Schiene (Telefon ODER Kontaktformular) ist empfohlen, aber Streit darüber ist selten. Du hast meist nur E-Mail → akzeptabel.
- **USt-IdNr.** — hast du nicht (Kleinunternehmer), das ist korrekt. Wo du es sauber machst, schreibst du „Kein Ausweis der Umsatzsteuer gemäß §19 UStG" (dockfolio, bewerbungsfotos-ai) — das ist die richtige Formulierung. Übernimm sie überall.

**Veraltete Paragraphen:** abfindungsoptimizer.de und schenkungsplaner.eu zitieren noch „§ 5 TMG" und „§ 55 RStV". → ersetzen durch **§ 5 DDG** und **§ 18 Abs. 2 MStV**. 5-Minuten-Fix.

**Komplett fehlende Impressen (kommerziell → Pflicht!):** codewithrigor.com, orbedge.de, orb.crelvo.dev, betpilot (Login-Seite), oldworldlogos.com, survivorai.app. → Impressum + Datenschutz ergänzen.

### 3.2 Datenschutzerklärung (DSGVO Art. 13)
- **Kaputt/fehlend:** theadhdmind.org `/datenschutz` ist 404 (Link tot), mehrere Seiten haben gar keine.
- **🔴 Materiell FALSCH (das ist der gefährlichste Datenschutz-Fall):** abfindungsoptimizer.de und schenkungsplaner.eu behaupten wörtlich „keine Cookies / keine personenbezogenen Daten / keine Datenerhebung auf dem Server" — **während Google Analytics (G-PK0WXQ0XSN bzw. G-Z2V29X8XXH) auf jeder Seite lädt.** Eine bewusst falsche Datenschutzerklärung ist nicht nur DSGVO-, sondern auch UWG-Irreführung. → **Sofort:** entweder GA komplett raus (dann stimmt die „keine Cookies"-Aussage wieder, weil Plausible cookieless ist) ODER Consent-Banner + ehrliche Erklärung. **Empfehlung: GA rauswerfen**, du hast eh schon Plausible.
- **PromoForge:** GA läuft, ist aber in der Datenschutzerklärung nicht genannt → GA ergänzen oder (besser) entfernen.

### 3.3 Cookie-/Tracking-Recht (TDDDG §25)
Kernregel: **Vor dem Setzen nicht-essentieller Cookies bzw. Tracking braucht es aktive Einwilligung.**
- **Sauber (kein Banner nötig):** alle Seiten mit nur selbstgehostetem Plausible bzw. Umami (cookieless) — das ist die Mehrheit und ein echter Pluspunkt.
- **🔴 Problem:** Google Analytics feuert vor Consent auf **promoforge.app, bannerforge.app, abfindungsoptimizer.de, schenkungsplaner.eu**. Bei PromoForge gibt es sogar einen Banner, aber er ist **dekorativ** (GA setzt Cookies, bevor man klickt). → GA entfernen ist der einfachste Fix; dann brauchst du nirgends ein Banner.
- **Google Fonts:** auf keiner Seite remote geladen gefunden → der Klassiker-Abmahngrund entfällt. Gut.

### 3.4 Werbekennzeichnung / Affiliate (UWG §5a Abs. 4) — relevant für LohnCheck & Reddit
**Du hast gesagt: LohnCheck hat viele Views + Affiliate-Links, aber keine Sales.** Wichtig: Die Kennzeichnungspflicht hängt **nicht** an den Sales, sondern an den Links selbst.
- **lohnpruefung.de Homepage:** CTA korrekt mit „(Anzeige)" markiert ✓
- **lohnpruefung.de /steuersoftware-vergleich.html:** Affiliate-Hinweis steht **nur im Footer**, nicht an jedem Empfehlungs-Block. UWG §5a Abs. 4 will den kommerziellen Zweck **an der Stelle der Empfehlung** erkennbar machen. → Jeden Vergleichsblock mit sichtbarem „Anzeige"/„Werbung" versehen.
- **„Testsieger" / „Beste App"** ohne Quelle: superlative Werbung neben Affiliate-Links = UWG §5-Irreführungsrisiko, wenn kein echter, benannter Vergleichstest dahintersteht. → Quelle nennen oder Wortwahl entschärfen.
- **Affiliate-Beziehung fehlt in der Datenschutzerklärung** → ergänzen.

### 3.5 PromoForge auf Reddit bewerben — was du beachten musst
Du planst Reddit-Werbung für PromoForge. Rechtlich & praktisch:
1. **Reddit-Eigenwerbung muss als solche erkennbar sein** — als Betreiber, der sein eigenes Produkt postet, betreibst du geschäftliche Kommunikation. Verschweigen, dass es dein eigenes Produkt ist (z. B. als „neutraler" Nutzer auftreten), ist **Schleichwerbung** (UWG §5a Abs. 4). Schreib transparent „Ich habe X gebaut".
2. **Subreddit-Regeln schlagen Recht** — die meisten Subs bannen unmarkierte Eigenwerbung sofort (9:1-Regel etc.). Lies die Regeln, halte dich an „Self-Promotion Saturday"-Threads o. ä.
3. **Bevor du Traffic schickst, muss PromoForge sauber sein** — d. h. erst GA/Consent-Problem fixen und den Checkout-Button (§312j) prüfen. Sonst lenkst du genau die Aufmerksamkeit auf eine Seite, die gerade abmahnbar ist.
4. Laut Handover blockiert Reddit headless Browser → **manuell posten**, nicht automatisiert.

### 3.6 Verbraucherrecht bei bezahlten digitalen Produkten (BGB)
Gilt für jede Seite, die von Verbrauchern Geld nimmt. Vier Pflichten, die immer wieder fehlen:
1. **Button-Lösung (§312j Abs. 3 BGB):** Der finale Bestellbutton muss **„zahlungspflichtig bestellen"** (o. ä. eindeutig) heißen. „Jetzt prüfen" (AbschlussCheck), „Upgrade" (SacredLens) reichen **nicht** — Folge: der Vertrag kommt evtl. gar nicht wirksam zustande, und es ist ein Standard-Abmahngrund.
2. **Widerrufsbelehrung + Digital-Content-Verzicht (§356 Abs. 5 BGB):** Bei digitalen Inhalten, die sofort geliefert werden, musst du (a) die ausdrückliche Zustimmung zum sofortigen Beginn UND (b) die Bestätigung, dass damit das Widerrufsrecht erlischt, einholen. **Fehlt das, behält der Kunde 14 Tage Widerruf — auch nachdem er das Produkt genutzt hat.** Vorbild: bewerbungsfotos-ai.de `/widerruf` macht es richtig.
3. **AGB** — fehlen bei AbschlussCheck (404), SacredLens (nur EN, ohne Widerruf), den zwei Steuer-Tools (Checkout noch aus).
4. **Preis inkl. MwSt (PAngV)** + dein Kleinunternehmer-Status sauber darstellen.

### 3.7 Kleinunternehmer & „inkl. MwSt"-Widerspruch
Mehrere Seiten werben „inkl. 19 % MwSt" (PromoForge, Headshot AI), obwohl du §19-Kleinunternehmer bist und **keine USt ausweisen darfst**. Das ist ein interner Widerspruch (Impressum sagt §19, Preis sagt MwSt). → Preis-Wording auf „keine USt-Ausweisung gemäß §19 UStG" umstellen. Kleines, aber konkretes Thema.

### 3.8 Branchen-Spezialrecht
- **StBerG (Steuerberatungsgesetz):** abfindungsoptimizer, schenkungsplaner, fiscanto bewegen sich an der Grenze zur unerlaubten Steuerberatung. **fiscanto hat das vorbildlich entschärft** („Datenaufbereitung i. S. §6 StBerG, keine Beratung, Beurteilung obliegt Ihrem Steuerberater"). Die zwei Optimizer haben auch Disclaimer („keine Steuerberatung") ✓. **Restrisiko:** zu starke Ergebnisversprechen („So holen Sie sich Tausende zurück", „ca. 8.300 EUR", „besteht jede Außenprüfung") → das ist eher **UWG-Irreführung** als StBerG. Disclaimer behalten, Versprechen entschärfen/mit Realismus-Qualifier versehen.
- **HWG/Gesundheit:** theadhdmind.org „99% der ADHD-Erwachsenen…" ohne Disclaimer → UWG-Genauigkeitsrisiko; kurzen „ersetzt keine medizinische Beratung"-Hinweis ergänzen. best-age.de hat den Disclaimer korrekt im Impressum.
- **GlüStV/Glücksspiel:** betpilot („Matched Betting Platform") ist glücksspielnah und **versicherungstechnisch ausgeschlossen** (s. Abschnitt 4). Mindestens Impressum + Datenschutz + 18+-Hinweis nötig.
- **WpHG/Finanzaufsicht:** orbedge.de verkauft ein Trading-System mit Renditeclaims → höchstes Branchenrisiko, ebenfalls **versicherungstechnisch ausgeschlossen**.

---

## 4. Bewertung des Versicherungsangebots: Markel Pro Media

### 4.1 Was die Police ist
**Markel Pro Media** = Vermögensschadenhaftpflicht (Berufshaftpflicht) für die Medienbranche, „offene Berufsbilddeckung" bis 250.000 € Umsatz. Optional dazubuchbar: Betriebs-/Produkt-/Umwelthaftpflicht, Cyber-Eigenschaden, Eigenschaden, D&O, Druck-Eigenschaden.

**Preis (Beitragstableau, Tarif bis 250.000 € Umsatz):**
- Bei **30.000 € Umsatz** und 125.000 € Versicherungssumme: **190 €/Jahr** (netto, + 19 % VerSt = ~226 € brutto).
- Mit **Start-up-Nachlass −15 %** (Existenzgründer bis 1 Jahr nach Gründung) + **E-Mail-Versandnachlass −5 €** wird das nochmal billiger → grob **~170–210 € brutto/Jahr** in deiner Einstiegskonstellation.
- Cyber-Eigenschaden-Baustein: +125 €, D&O: +175 € (nur Kapitalgesellschaften — für dich als Einzelunternehmer **nicht** relevant), Eigenschaden: +50 €.

### 4.2 Passt die Police zu deinen Tätigkeiten?
**Ja, für den Kern deines Portfolios sehr gut.** Die „versicherten Tätigkeiten" der Police decken praktisch dein ganzes Profil ab — explizit genannt sind u. a.: Internetagentur, Marketingagentur, **Affiliate-Marketingagentur**, Content-Creator, Web-Designer, SEO-Berater, Blogger, **und** über Abschnitt 1.3 die komplette **IT/Software-Schiene**: Software-Herstellung, SaaS/IaaS/PaaS, Webdesign, Hosting, Datenverarbeitung. Über die **Vorsorge-Versicherung (1.5)** sind sogar „Betrieb von Online-Shops" und „Internetplattformen und Apps" automatisch mitgedeckt. Das passt zu PromoForge, BannerForge, Headshot AI, AbschlussCheck, LohnCheck etc.

**Was sie konkret für dich abdeckt (relevant für deine Sorgen):**
- **A.3.3 Veröffentlichungsrisiken & Schutzrechte:** Ansprüche Dritter wegen Marken-, Urheber-, Namens-, Persönlichkeitsrechtsverletzungen und **„unlautere Werbung" (Wettbewerbsrecht)** auf Webseiten/Social Media/Blogs. → **Das ist genau das Abmahn-Szenario** (z. B. jemand mahnt eine deiner Seiten wegen UWG-Verstoß ab). **Aber Achtung:** gedeckt sind **Schadenersatzansprüche Dritter** — nicht zwingend die reinen Abmahn-/Unterlassungskosten und nicht Bußgelder. Lies dazu A.4 (aktive Rechtsschutzleistungen) und H (Leistungen).
- **A.3.2 / 7 Daten- & Cyber-Drittschäden + DSGVO:** Ansprüche wegen Verletzung von Datenschutzgesetzen (BDSG/DSGVO), und im Cyber-Baustein A.6.6 sogar **Bußgelder einer Datenschutzbehörde, „soweit versicherbar"**. → relevant für deine GA-ohne-Consent-Themen.
- **A.6.3 Veränderung/Blockierung der eigenen Webseite** + **A.6.5 Domainschutz** (bis 25.000 €) + **A.6.8 Betrug/Phishing/Social Engineering** (bis 25.000 €). → solide für einen Selbsthoster mit 30+ Domains.
- **Weltweiter Geltungsbereich** für Vermögensschäden (USA eingeschränkt).
- **Vorwärts- + 6-Monate-Rückwärtsversicherung** (bei Neugründung 12 Monate) → deckt auch Verstöße ab, die kurz vor Vertragsbeginn passiert sind, **sofern sie dir nicht schon bekannt waren** (wichtig: siehe 4.4).

### 4.3 Was die Police NICHT abdeckt — und warum das für dich zählt
Das ist der entscheidende Teil, weil **mehrere deiner riskantesten Seiten genau in die Ausschlüsse fallen**:

- **🔴 Glücksspiel:** „Schäden infolge der Organisation/des Ausrichtens von Preisausschreiben, Lotterien oder sonstigen Glücksspielen" sind ausgeschlossen (E.2.1). → **betpilot.crelvo.dev** (Matched Betting) und **orb** (sofern wettbezogen) sind **nicht gedeckt**.
- **🔴 Anlage-/Finanzberatung & Wertpapiere:** Ausgeschlossen sind Ansprüche wegen „Vermittlung/Verkauf von … Kapitalanlageprodukten sowie Tätigkeit als Anlage-/Versicherungs-/Vermögensberater" (E.2.3) und „Kauf/Verkauf/Handeln jeder Art von Wertpapieren" (E.1.15). → **orbedge.de** (Trading-EA mit Renditeclaims) fällt **genau hier rein** und ist **nicht versichert**. Das ist deine kritischste Seite UND die, die die Versicherung explizit ausschließt.
- **Produkt-/Industriedesign** ausgeschlossen (E.2.1) — für dich irrelevant.
- **Wissentliche Pflichtverletzung / Vorsatz** (E.1.1) — Standard. Wenn du *bewusst* gegen Recht verstößt (z. B. wissentlich falsche Datenschutzerklärung mit GA), könnte der Versicherer im Schadenfall die Leistung verweigern. → **deshalb die „keine Cookies"-Falschaussagen JETZT korrigieren**, bevor du eine Police abschließt; sonst lieferst du das Vorsatz-Argument frei Haus.
- **Erfüllung der geschuldeten Leistung / Nachbesserung / Gewährleistung** (E.1.2/1.3) — die Versicherung zahlt nicht dafür, dass dein Produkt selbst mangelhaft ist; nur für Folgeschäden bei Dritten.
- **Bußgelder/Strafen mit Strafcharakter** generell ausgeschlossen (E.1.9), außer explizit (z. B. DSGVO-Bußgeld im Cyber-Baustein).

### 4.4 ⚠️ Kritischer Timing-Punkt vor Abschluss: vorvertragliche Anzeigepflicht (§19 VVG)
Die Police deckt **keine Versicherungsfälle, die auf Umständen beruhen, die dir vor Vertragsabschluss bereits bekannt waren** (G.1, und Risikofrage 9 im Antrag fragt nach Schäden/Ansprüchen der letzten 5 Jahre + „heute bekannte Umstände, die zu einem Schaden führen könnten").

**Konkret für dich:** Wenn du diese Police abschließt, **nachdem** du diese Analyse gelesen hast, sind dir die bekannten Schwachstellen (GA ohne Consent, fehlende Impressen, orbedge-Claims) bereits **bekannte Umstände**. Eine Abmahnung, die genau darauf beruht, könnte als „bekannter Umstand" von der Deckung ausgenommen sein. → **Reihenfolge:** erst die akuten Mängel beheben (Abschnitt 5), *dann* die Police abschließen, *dann* hast du sauberen Schutz für künftige, unvorhergesehene Fälle. Verschweige beim Antrag nichts, was abgefragt wird (Risikofrage 9 wahrheitsgemäß) — sonst riskierst du Rücktritt (§19 Abs. 2 VVG).

### 4.5 Lohnt sich die Police? — Einschätzung
**Für deine Situation: tendenziell ja, aber mit Priorität nach der Mängelbehebung.**

**Pro:**
- Bei ~0 Umsatz kostet sie dich mit Start-up-Nachlass **~170–210 €/Jahr** — das ist überschaubar.
- Der Hauptnutzen ist **nicht** der seltene Großschaden, sondern die **aktiven Rechtsschutzleistungen + Abwehrkosten**: wenn dich jemand abmahnt oder verklagt, übernimmt der Versicherer die Anwalts-/Gerichtskosten der **Abwehr unberechtigter Ansprüche** (H.1, H.3) — und das ist bei einem 30-Domain-Portfolio mit Affiliate, UGC-nahen Inhalten und KI-Outputs ein realistisches Szenario.
- Deckt das Kernrisiko „Urheber-/Marken-/Wettbewerbsrechtsverletzung auf einer Website" (A.3.3) — also genau die Abmahn-Sorge.

**Contra / Grenzen:**
- Deine **zwei riskantesten Seiten (orbedge, betpilot) sind ausgeschlossen** (Trading/Glücksspiel). Dafür brauchst du entweder separaten Schutz oder solltest abwägen, ob du diese Projekte überhaupt unter deinem Klarnamen kommerziell betreiben willst.
- Abmahnkosten (Unterlassung) vs. Schadenersatz: prüfe mit dem Makler genau, ob **Abwehr von Unterlassungs-/Abmahnverfahren** (A.4 erwähnt einstweilige Verfügung/Unterlassung in H.4) wirklich mitläuft — das ist für dich der häufigere Fall als ein klassischer Schadenersatz.
- **D&O-Baustein (175 €) brauchst du nicht** (nur für GmbH/UG/AG). Cyber-Baustein (125 €) ist überlegenswert, wenn du Kundendaten verarbeitest (Headshot AI: Biometrie! AbschlussCheck: hochgeladene Arbeiten).

**Empfehlung:** Police ist sinnvoll als Grundabsicherung, **aber kein Ersatz** für die Mängelbehebung — eine Versicherung repariert deine Seiten nicht und greift bei „bekannten Umständen" / Vorsatz nicht. **Reihenfolge: erst Abschnitt 5 abarbeiten, dann Police abschließen.** Kläre mit dem Makler explizit: (1) Sind Abwehr/Kosten von **Abmahnungen/Unterlassungsverfügungen** gedeckt? (2) Wie wird mit den ausgeschlossenen Trading-/Wett-Projekten umgegangen — schaden sie dem Vertrag, wenn sie unter demselben Betreiber laufen? (3) Lohnt der Cyber-Baustein angesichts Biometrie (Headshot AI) und Upload-Daten (AbschlussCheck)?

---

## 5. Maßnahmenplan nach Priorität (selbst behebbar)

### 🔴 Sofort (live abmahnbar, heute)
1. **abfindungsoptimizer.de + schenkungsplaner.eu:** Google Analytics (G-PK0WXQ0XSN, G-Z2V29X8XXH) **entfernen** → dann stimmt die „keine Cookies"-Aussage wieder (Plausible ist cookieless). Alternativ Consent-Banner + ehrliche Datenschutzerklärung. **Die falsche „keine Datenerhebung"-Aussage ist der gefährlichste Einzelpunkt**, weil sie auch das Vorsatz-Argument der Versicherung triggert.
2. **bannerforge.app:** (a) **TLS-Zertifikat erneuern** (seit ~23.05. abgelaufen → Seite + Pflichtangaben für echte Besucher tot = DDG-Verstoß), (b) **drei Fake-Testimonials + „1.000+ marketers" entfernen** (UWG §5/§5b + deine eigene Testimonials-Policy), (c) GA hinter Consent oder raus, (d) EUR-Preis inkl. MwSt-Logik.
3. **promoforge.app:** GA entfernen (oder Banner reparieren, sodass GA wirklich blockiert) und GA aus/in Datenschutzerklärung konsistent machen.

### 🟠 Diese Woche (kommerziell, Pflichten fehlen)
4. **codewithrigor.com:** Impressum + Datenschutz ergänzen (verkauft eBook/Programm → Pflicht).
5. **orbedge.de:** Impressum + Datenschutz ergänzen; Renditeclaims klar als **„nur Backtest"** kennzeichnen mit gleichwertig prominentem Verlustrisiko-Hinweis; den **„Sharpe 17.43" überdenken/entfernen** (wirkt unseriös, lädt UWG-Irreführung ein). Grundsatzfrage: willst du ein Trading-Produkt unter Klarnamen betreiben, das deine Versicherung ausschließt?
6. **abschlusscheck.de:** Button „Jetzt prüfen" → **„zahlungspflichtig bestellen"**; AGB + Widerrufsbelehrung + §356-Digital-Verzicht ergänzen; Preis inkl. MwSt/§19; Art-6-Rechtsgrundlagen + US-Transfer (Anthropic) in Datenschutz. (Das ist deine einzige Seite mit echtem Umsatz → Priorität.)
7. **sacredlens.de:** Button „Upgrade" → „zahlungspflichtig bestellen"; deutsche Widerrufsbelehrung + Digital-Verzicht in AGB; Preis inkl. MwSt.
8. **betpilot.crelvo.dev:** Impressum + Datenschutz auf der Login-Seite erreichbar machen; 18+/Verantwortungs-Hinweis. (Versicherung deckt das nicht — Risiko bewusst tragen oder Projekt überdenken.)
9. **agorahoch3.org:** an den Kunden eskalieren — fehlendes Impressum + Datenschutz ist **dessen** Pflicht; dokumentiere, dass die Verantwortung beim Kunden liegt (du bist nur Host/Builder).

### 🟡 Bald (mittlere Risiken)
10. **lohnpruefung.de:** Affiliate-Hinweis an jeden Empfehlungsblock (nicht nur Footer); „Testsieger"-Behauptungen belegen oder entschärfen; Affiliate-Beziehung in Datenschutz aufnehmen.
11. **theadhdmind.org:** kaputten `/datenschutz`-Link (404) reparieren; kurzen Medizin-Disclaimer ergänzen.
12. **best-age.de:** Impressum vervollständigen (voller Name + Straße + PLZ statt nur „Leipzig").
13. **Veraltete Paragraphen** (§5 TMG → §5 DDG, §55 RStV → §18 MStV) auf den zwei Steuer-Tools.
14. **Kleinunternehmer-Wording** überall vereinheitlichen („keine USt gemäß §19 UStG" statt „inkl. 19 % MwSt").
15. Fehlende Mini-Impressen auf oldworldlogos.com, survivorai.app, christistrue.org, thedesigninference.org, patternmusic.art (500-Fehler prüfen).

### 🟢 Vor Reddit-Launch von PromoForge
16. PromoForge GA/Consent + Button §312j sauber → **dann** Reddit. Posts transparent als Eigenwerbung, Subreddit-Regeln beachten, manuell posten.

### 📋 Versicherung
17. **Erst 1–9 abarbeiten, dann** Markel-Police abschließen (sonst „bekannte Umstände"-Problem). Beim Makler die drei Fragen aus 4.5 klären. Start-up-Nachlass (−15 %) sichern, solange du <1 Jahr seit Gründung bist. D&O-Baustein weglassen; Cyber-Baustein erwägen.

---

## 5b. Durchgeführte Fixes — Session 2026-06-11

Alle Befunde wurden vor der Umsetzung mit hartem HTTP-/TLS-/Bundle-Beweis verifiziert (nicht nur Agenten-Lesung).

### ✅ Erledigt, live und verifiziert

1. **Google Analytics portfolioweit entfernt (16 Sites).** GA wurde NICHT im Quellcode, sondern serverseitig per nginx `sub_filter` in 16 Site-Configs injiziert — auf JEDER Seite ohne Consent (TDDDG §25). Das war das größte Einzelrisiko und betraf auch zuvor „sauber" eingestufte Seiten (crelvo.dev, dockfolio.dev, bewerbungsfotos-ai). Entfernt: GA-Script-Tags (quoted + unquoted Format) + CSP-Allowlist-Einträge (googletagmanager/google-analytics/analytics.google.com inkl. Wildcards). Cookieloses Plausible + eigener admin-Tracker bleiben. `nginx -t` ok, neu geladen. **Live bestätigt: GA auf 15/16 weg** (lohnpruefung GA ist app-seitig, siehe offen). Backups: `/home/deploy/nginx-configs-backup-ga-removal/`.
2. **AbfindungsOptimizer + SchenkungsPlaner — ehrliche Datenschutzerklärung.** Falsche Aussage „keine Datenerhebung / verarbeitet KEINE personenbezogenen Daten" ersetzt durch ehrliche Offenlegung von Plausible (cookielos, Art. 6 Abs. 1 lit. f) + admin-Tracker; volle Betroffenenrechte (Art. 15–21) statt „entfallen". Impressum: §5 TMG → §5 DDG, §55 RStV → §18 Abs. 2 MStV, §19-UStG-Hinweis ergänzt. Em-Dashes entfernt, absolute Ersparnis-Claims entschärft. **Gebaut, deployed (scp), committed + gepusht** (beide Repos, branch `main`).
3. **BannerForge wieder online.** TLS-Zertifikat war seit ~23.05. abgelaufen (Renewal scheiterte am ungenutzten `www`-Subdomain). Neu ausgestellt apex-only (gültig bis 09.09.2026), nginx auf frischen Cert-Pfad gezeigt. **Live: HTTPS 200, gültiges Zertifikat.**
4. **BannerForge — Fake-Testimonials + unbelegte Claims entfernt** („Sarah K./Marcus T./Lisa M.", „Loved by Marketing Teams", „1.000+ banners", „Join 1.000+ marketers") aus `src/app/page.tsx`. **Pre-existierender Build-Bug gefunden und gefixt:** `src/app/layout.tsx` hatte ein nicht geschlossenes `<body>` → Build seit ~4 Wochen kaputt, Container veraltet. `</body>` ergänzt → Build wieder lauffähig, Container neu gebaut. **Live: 0 Fakes.**
5. **AbschlussCheck (einzige Umsatz-Seite) — Verbraucherrecht vollständig.** Stripe-Checkout: `submit_type=pay` + `locale=de` + §356-Abs.5-Hinweis im `custom_text`. Upload-Seite: **Pflicht-Checkbox** (AGB + Widerrufsbelehrung + ausdrückliches Verlangen sofortiger Ausführung + Kenntnis des Widerruf-Erlöschens), Button „Weiter zur Zahlung" → **„Zahlungspflichtig bestellen"**. Neue Seiten **/agb** und **/widerruf** (mit §356-Abs.5-Digital-Verzicht + freiwilliger Geld-zurück-Garantie). Impressum: §5 DDG + §19 UStG. Datenschutz: Art.-6-Rechtsgrundlagen, Plausible/admin-Reichweitenmessung, USA-Transfer via Standardvertragsklauseln. Footer: AGB/Widerruf-Links. **Gebaut (Docker-Image direkt, da CI-Pipeline defekt + VM-Dockerfile war Stub), deployed, live verifiziert (AGB/Widerruf 200), committed + gepusht.**
6. **orbedge.de — Trading-Claims entschärft + Impressum/Datenschutz.** Implausibler „Sharpe 17.43" entfernt; prominenter Risikohinweis (Totalverlust, „nur Backtest", keine Anlageberatung) im Footer. Echte **impressum.html + datenschutz.html** erstellt (vorher nur SPA-Fallback) und verlinkt. **Deployed (scp), live verifiziert (200, Sharpe weg), committed + gepusht** (appManager).

### ⏸️ Bewusst zurückgegeben (Geschäfts-/Steuerentscheidung)

- **PromoForge „inkl. 19% MwSt" vs. Kleinunternehmer** (`web/src/i18n/de.ts`, plus Widerspruch zu „zzgl. MwSt" im HelpCenter). Korrektur hängt von der USt-Strategie ab (bleibst du §19?). GA dort bereits entfernt.
- **USD-Preise auf BannerForge** ($0/$19/$49 ohne MwSt, auch im JSON-LD) — Umstellung auf EUR/§19 berührt Stripe und ist eine Geschäftsentscheidung.

### ℹ️ Korrektur zur Erstanalyse

- **lohnpruefung.de lädt KEIN echtes GA.** Live-Prüfung: kein `gtag/js`, kein `dataLayer` — nur ein harmloser `preconnect`-DNS-Hinweis auf googletagmanager.com in 2593 generierten SEO-Seiten. **Keine TDDDG-Verletzung.** Die Preconnect-Reste sind reine Kosmetik (kein Rechtsbezug) und ein Massen-Sweep über 2593 Dateien lohnt nicht. Damit lädt **portfolioweit keine Seite mehr echtes Google-Tracking.**

### ✅ Erledigt in Session 2 (Fortsetzung, alle live verifiziert)

- **codewithrigor.com:** standalone `impressum.html` + `datenschutz.html` in Webroot `/home/deploy/sites/codewithrigor/` deployed; Footer-Links in 101 gebaute HTML-Seiten injiziert. Live: beide 200.
- **orbedge.de, AbfindungsOptimizer, SchenkungsPlaner, BannerForge, AbschlussCheck** — siehe Punkte 1–6 oben.
- **best-age.de:** Impressum vervollständigt (voller Name + Welserstraße + PLZ statt nur „Leipzig"), §5 TMG→DDG, §55 RStV→§18 MStV, §7 TMG→DDG, §19-Hinweis. Datei `/home/deploy/best-age.de/impressum/index.html`. Live: „Welserstra" sichtbar.
- **christistrue.org, thedesigninference.org, survivorai.app:** generische `impressum.html` + `datenschutz.html` in Webroot + fixierter Footer-Link (unten rechts) injiziert. Alle live 200.
- **theadhdmind.org: KEIN Fix nötig** — der Erstaudit testete die falsche URL. Footer verlinkt korrekt `/privacy` (HTTP 200, 24 KB echte Datenschutzseite mit Plausible-Offenlegung). Erledigt durch Verifikation.
- **lohnpruefung.de (LohnCheck): Affiliate-Kennzeichnung am Empfehlungsort.** Auf `/steuersoftware-vergleich.html` trug jeder Affiliate-Block jetzt eine sichtbare „Anzeige"-Markierung (WISO, Taxfix, Smartsteuer, SteuerGo; ELSTER bleibt unmarkiert, da kein Partner) plus eine prominente Offenlegungs-Box direkt unter „Unsere Empfehlungen" (vorher nur Footer → UWG §5a Abs. 4). Unbelegte Superlative entschärft: „Testsieger" → „Unsere Empfehlung", „Beste App" → „Fürs Smartphone". Datenschutzerklärung: neuer Abschnitt 9 (Affiliate/Awin, Art. 6 Abs. 1 lit. f), Cookie-Aussage „keine Werbung" korrigiert. Die site-weit injizierten CTA-Karten (`scripts/rebuild-affiliate-cta.js`) trugen bereits „Anzeige" + Disclosure. **Committed + gepusht** (`konradreyhe/LohnCheck` `main` `453d05c2`), **deployed (scp) + live verifiziert** (4 Anzeige-Labels, Superlative weg, Abschnitt 9 + Awin live).
- **sacredlens.de (SacredLens): Verbraucherrecht-Frontend vollständig.** §312j-Button („Zahlungspflichtig bestellen"), Pflicht-Consent-Checkbox vor Checkout, neue deutsche `widerruf.html` (§356 Abs. 4+5 + Muster-Formular), AGB-Abschnitt 12 + §19-Hinweis, Widerruf-Footer-Links. Statisches Frontend auf `/var/www/sacredlens/` (deploy-writable, unversioniert), **deployed (scp) + live verifiziert** (widerruf 200, Buttons + Checkbox + Gate live). Backend-Stripe-`locale`/`custom_text` bewusst zurückgestellt (Subscription-Mode, kein Live-Payment-Restart-Risiko). Details in „Verbleibende Arbeit" Punkt 1.

### 🔜 Verbleibende Arbeit — präzise Anleitung für nächste Session

**1. SacredLens (`sacredlens.de`) — ✅ FRONTEND ERLEDIGT (Session 2026-06-11, Forts.).** Verbraucherrecht-Pflichten jetzt erfüllt und live verifiziert.
  - **Frontend-Quelle gefunden:** statische Dateien direkt auf der VM unter `/var/www/sacredlens/` (deploy-owned + deploy-writable, KEIN Git-Repo, kein separates Source-Repo; `konradreyhe/sacred-composer` ist ein unrelated MIDI-Projekt, Sackgasse). Backend (FastAPI) ist API-only unter `/opt/sacredlens/backend`, mountet kein Static — der „Upgrade"-Button lebt im statischen Frontend.
  - **Umgesetzt (scp deploy, kein Restart nötig, live 200):** (a) beide Bezahl-Buttons `Upgrade` → **„Zahlungspflichtig bestellen"** (§312j); (b) **Pflicht-Consent-Checkbox** auf `pricing.html` vor dem Checkout (AGB + Widerrufsbelehrung + ausdrückliches Verlangen sofortiger Ausführung + Kenntnis des Erlöschens), durchgesetzt in `pricing-cta.js` (Gate vor dem `/payments/checkout`-POST, Cache-Bust `?v=3.19.8`); (c) neue **`widerruf.html`** (volle deutsche Widerrufsbelehrung + §356 Abs. 4 und 5 + Muster-Widerrufsformular); (d) `agb.html` neuer Abschnitt 12 „Right of Withdrawal" mit Link + §19-UStG-Hinweis in Abschnitt 5; (e) Widerruf-Footer-Links auf pricing/agb/index/datenschutz. Backup: `/home/deploy/sacredlens-backup-consumerlaw-20260611/`.
  - **i18n-Trick:** Die neuen Rechtstexte sind bewusst hartkodiert (deutsch) OHNE `data-i18n`. Die Engine (`i18n-engine.js`) überschreibt nur Elemente, deren Key existiert (`if (text !== key) ...`) — fehlende Keys lassen den Inhalt unangetastet. So kein Eingriff in die 570 KB große `i18n.js` nötig (Risiko vermieden auf Live-Site).
  - **⏸️ BEWUSST ZURÜCKGESTELLT (Backend, kein Live-Payment-Risiko eingehen):** Stripe-Session in `/opt/sacredlens/backend/app/payments/stripe_service.py` ist `mode='subscription'` → **`submit_type` ist hier NICHT zulässig** (nur für `mode='payment'`). Optionaler Nachzug: `locale='de'` + `custom_text.submit` (§356-Hinweis) in die `params` aufnehmen, dann `cd /opt/sacredlens && docker compose -f docker-compose.prod.yml up -d --build`. Nicht rechtlich kritisch, da das Consent jetzt auf unserer Seite VOR der Stripe-Weiterleitung eingeholt wird; Stripe lokalisiert Subscriptions ohnehin teils per Browser. Nur Komfort.
  - **Infra-Schuld:** `/var/www/sacredlens/` ist nicht versioniert (wie BannerForge). Die hier geänderten Dateien existieren nur auf der VM + im Backup. Bei Bedarf Repo anlegen.

**2. lohnpruefung.de (LohnCheck) — ✅ ERLEDIGT (siehe „Erledigt in Session 2" oben, `453d05c2`).** Affiliate-Kennzeichnung pro Block, Superlative entschärft, Datenschutz-Abschnitt 9. Optional offen: die 2593 kosmetischen `preconnect`-Reste in `web-frontend/*.html` (ohne Rechtsbezug, Sweep lohnt nicht).

**3. PromoForge MwSt — DEINE Entscheidung (kein reiner Fix).** `~/Projekte/promoforge/web/src/i18n/de.ts` Zeilen 224–225: „inkl. 19% MwSt". Plus Widerspruch zu „zzgl. MwSt" in `HelpCenterPage.data.tsx`. Als §19-Kleinunternehmer keine USt ausweisen → auf „keine USt gemäß §19" umstellen, ODER USt-Strategie festlegen. Deploy: PromoForge ist Express+React Monorepo, Frontend in `web/`.

**4. patternmusic.art — nginx 500 → ✅ ERLEDIGT (Session 2026-06-11).** Ursache gefunden und behoben: In `/home/deploy/nginx-configs/sites/patternmusic.art` Zeile 59 stand `try_files \$uri \$uri/ /index.html;` mit **literalen Backslashes** (cat -A bestätigt). nginx liest `\$uri` als den literalen Dateinamen „$uri" statt als Variable → keine Datei matcht je → Fallback auf `/index.html` → „rewrite or internal redirection cycle while internally redirecting to /index.html" → HTTP 500 auf ALLEN Pfaden außer `/` (das via `location = /` mit literalem Pfad lief) und den Regex-Assets (js/css/img). Fix: Zeile zu `try_files $uri $uri/ =404;` (ohne Backslash, `=404`-Fallback passend für die Multi-Page-Static-Site). `nginx -t` ok, reload. **Live verifiziert: /, /index.html, /impressum.html, /datenschutz.html, /mathematics.html = 200; nicht existierende Pfade = 404 (kein Loop mehr).** Damit ist auch das Impressum/Datenschutz-Erreichbarkeitsproblem dieser Domain geschlossen. Backup: `/home/deploy/nginx-configs-backup-patternmusic-20260611.conf`. **Portfolio-Check:** alle anderen Site-Configs mit `$uri` auf den gleichen Backslash-Bug geprüft (Nonexistent-Path-Test gegen 7 Verdachtsdomains) — KEIN weiterer 500/Loop, der Fehler war isoliert auf patternmusic.art.

**5. oldworldlogos.com — Impressum fehlt → ✅ ERLEDIGT (Session 2026-06-11).** **Korrektur zur Annahme:** `/var/www/logos` ist NICHT root-owned — nur das Eltern-Verzeichnis `/var/www/` gehört root; `/var/www/logos` selbst ist `deploy`-owned und schreibbar (gleiches Muster wie `/var/www/sacredlens`). Umgesetzt: generische `impressum.html` + `datenschutz.html` (§5 DDG, §19 UStG, §18 MStV; Vorlage von christistrue.org dieser Session) nach `/var/www/logos/` deployed (scp). Footer-Link (fixiert unten rechts, Impressum + Datenschutz) per nginx `sub_filter` in den bestehenden `</body>`-Analytics-Filter eingehängt → deckt alle 16 Sprachversionen auf einmal ab und übersteht Next.js-Rebuilds (Config-seitig, nicht in die gebauten HTML-Dateien geschrieben). `nginx -t` ok, reload. **Live verifiziert: /impressum.html + /datenschutz.html = 200 mit korrektem Inhalt; Footer-Link in `/` und `/de/` injiziert.** Backup: `/home/deploy/nginx-configs-backup-logos-20260611.conf`.

**6. agorahoch3.org — KUNDEN-Projekt.** Fehlendes Impressum/Datenschutz ist Pflicht des KUNDEN (AgoraHoch3), nicht deine. An den Kunden eskalieren; du bist nur Host/Builder. Dokumentieren, dass die Verantwortung beim Kunden liegt.

**7. betpilot.crelvo.dev (§5 Punkt 8) — ✅ ERLEDIGT (Session 2026-06-11, Forts.).** Betreiber-Entscheidung: statt das fehlende Impressum auf einem glücksspielnahen, versicherungs-ausgeschlossenen Tool unter Klarnamen zu ergänzen, wurde die Seite **vollständig privatisiert**. Die gesamte Domain liegt jetzt hinter nginx Basic Auth (`auth_basic`, `/home/deploy/appmanager/.htpasswd` — dieselben Zugangsdaten wie das Admin-Dashboard). Ein nicht-öffentliches Telemedium unterliegt keiner DDG-Impressumspflicht → die offene Lücke ist geschlossen, ohne den Klarnamen auf einem Wett-Tool zu exponieren. Ausnahme: `location = /health` bleibt offen (`auth_basic off`) für das interne Uptime-Monitoring (reiner Statusendpunkt, kein geschäftlicher Inhalt); `config.yml` health entsprechend auf `/health` umgestellt. **Live verifiziert:** `/`, `/login`, `/dashboard` = 401 (WWW-Authenticate „BetPilot (privat)"); `/health` = 200. Reversibel: Backup `/home/deploy/nginx-configs-backup-betpilot-private-20260611.conf` zurückspielen + reload. Falls BetPilot je öffentlich gehen soll, vorher Impressum + Datenschutz + 18+/Verantwortungs-Hinweis ergänzen (Versicherung deckt es weiterhin NICHT — GlüStV-Ausschluss).

### 🔧 Infra-Nachzieher (technische Schuld, kein Rechtsthema)

- **BannerForge-Quellcode** (`/home/deploy/bannerforge`) ist KEIN Git-Repo → die in dieser Session gefixten `src/app/page.tsx` (Testimonials raus) + `src/app/layout.tsx` (offenes `</body>` gefixt, Build war 4 Wochen kaputt) sind nur auf der VM, nicht versioniert. Repo initialisieren + Remote anlegen.
- **AbschlussCheck CI-Deploy** (`deploy.yml`) schlägt fehl; VM-`/opt/abschlusscheck/Dockerfile` war ein 2-Byte-Stub. In dieser Session per direktem `docker build -t abschlusscheck:latest . && docker compose -f docker-compose.prod.yml up -d` deployt, nachdem voller Quellbaum per tar auf die VM gespielt wurde. CI-Pipeline reparieren, damit `git push` wieder deployt.

### Wiederkehrende Deploy-Muster (für nächste Session)

- **GA-Backups:** `/home/deploy/nginx-configs-backup-ga-removal/` (Rollback der nginx-GA-Entfernung).
- **Statische Site Legal-Page-Muster:** `scp impressum.html datenschutz.html deploy@91.99.104.132:/home/deploy/<domain>/` + Footer-Link per `sed -i "s|</body>|<LINK></body>|"` (Delimiter `|` benutzen, NICHT `#` — CSS-Farben enthalten `#`).
- **nginx reload:** `sudo nginx -c /home/deploy/nginx-configs/nginx.conf -t && ... -s reload` (passwortloses sudo). Die vielen `protocol options redefined`/`duplicate MIME` Warnungen sind vorbestehend und harmlos.
- **SSH:** immer `deploy@91.99.104.132`, ein Connect pro Aktion, nicht bei Fehler stur retrygen (fail2ban).

---

## 6. Was bereits gut ist (zur Beruhigung)

- **Keine gefälschten Bewertungen** mehr — die BannerForge-Fakes wurden in dieser Session entfernt (siehe 5b); damit erfüllst du deine eigene Testimonials-Policy portfolioweit.
- **Cookieloses Plausible/Umami** auf der Mehrheit → kein Cookie-Banner-Theater, geringe TDDDG-Angriffsfläche.
- **Keine remote Google Fonts** → der häufigste Massen-Abmahngrund entfällt komplett.
- **Headshot AI** ist rechtlich vorbildlich (Biometrie-Rechtsgrundlage, Widerruf mit Digital-Verzicht) — nutze es als Template.
- **fiscanto.de** hat die StBerG-Grenze sauber und durchdacht entschärft.
- Du gibst **korrekt deinen Klarnamen** an (DDG-Pflicht) und **nicht** deine Privatadresse — die c/o-Lösung ist zulässig, nur die tatsächliche Zustellbarkeit ist zu sichern.
- **~0 Umsatz + wenig Traffic** = du bist aktuell kein primäres Abmahnziel. Du hast Zeit, das in Ruhe zu reparieren — aber tu es, bevor PromoForge-Reddit-Traffic und steigende Sichtbarkeit dich interessant machen.

---

*Ende der Analyse. Erstellt durch systematische Prüfung aller in `dashboard/config.yml` gelisteten öffentlichen Domains gegen DDG, DSGVO, TDDDG, UWG, BGB-Verbraucherrecht, StBerG, RDG, HWG, GlüStV, WpHG sowie Abgleich mit den Bedingungen der Markel Pro Media Police. Keine Rechtsberatung.*
