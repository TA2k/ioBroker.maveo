![Logo](admin/maveo.png)
# ioBroker.maveo

[![NPM version](https://img.shields.io/npm/v/iobroker.maveo.svg)](https://www.npmjs.com/package/iobroker.maveo)
[![Downloads](https://img.shields.io/npm/dm/iobroker.maveo.svg)](https://www.npmjs.com/package/iobroker.maveo)
![Number of Installations](https://iobroker.live/badges/maveo-installed.svg)
![Current version in stable repository](https://iobroker.live/badges/maveo-stable.svg)

[![NPM](https://nodei.co/npm/iobroker.maveo.png?downloads=true)](https://nodei.co/npm/iobroker.maveo/)

**Tests:** ![Test and Release](https://github.com/TA2k/ioBroker.maveo/workflows/Test%20and%20Release/badge.svg)

## maveo Adapter für ioBroker

Adapter für die maveo Garagentor-Systeme der Firma Marantec. Zwei Betriebsmodi:

- **Cloud-Modus (default)** — Login über die Marantec-Cloud (Amazon Cognito),
  Steuerung über den Nymea-Tunnel `wss://remoteproxy.nymea.io`.
  Setzt voraus, dass die Box in der maveo-App **per Bluetooth-Onboarding**
  gepairt wurde (die App schreibt dabei die Cognito Identity ID in die Box).
  Wenn die Box "nur lokal" hinzugefügt wurde, ist die Cloud-Device-Liste leer –
  in dem Fall stellt der Adapter im Log darauf hin und du kannst auf LAN-Modus
  umschalten.
- **LAN-Modus** — direkte JSON-RPC-Verbindung zur Box (`<boxIp>:2222` per TLS
  standardmäßig). Beim ersten Start wird per Push-Button-Auth authentifiziert:
  gelbe Taste hinten an der maveo-Box innerhalb von 60 s drücken, der erhaltene
  Token wird im Adapter gespeichert. Funktioniert unabhängig vom Cognito-Konto
  und ist die zuverlässige Variante, wenn die Box im lokalen Netz erreichbar ist.

Alle Zustände (Position, Bewegung, Sensoren) kommen in beiden Modi als
Push-Notifikation über `Integrations.StateChanged`, das Öffnen/Schließen erfolgt
über `Integrations.ExecuteAction`.

## Konfiguration

| Feld | Bedeutung | Default |
|---|---|---|
| `App Email` / `App Password` | Zugangsdaten aus der maveo-App (nur Cloud-Modus) | — |
| `Region` | `eu` (Europa) oder `us` (USA) | `eu` |
| `IoT wake topic` | Optionales AWS-IoT-Topic zum Aufwecken der Box | leer |
| `Maveo box IP` | LAN-Modus aktivieren, sobald gesetzt | leer |
| `Port` | JSON-RPC Port | 2222 |
| `TLS` | SSL für den JSON-RPC-Socket | an |

Die Cognito-Pool- und Client-IDs sowie die IoT-Endpunkte sind fest aus der
maveo-App 2.6.1 hinterlegt und regionabhängig. Der lokale Push-Button-Token
wird verschlüsselt in `native.localToken` abgelegt.

## Steuerung

Für jedes Thing werden unter `maveo.<inst>.<thingId>.remote.<action>` schreib-
bare States angelegt (z. B. `open`, `close`). Setzen auf einen beliebigen Wert
löst `Integrations.ExecuteAction` aus. Statusänderungen kommen automatisch als
Push-Update in `maveo.<inst>.<thingId>.<stateTypeId>`.

## Diskussion und Fragen

https://forum.iobroker.net/topic/48101/test-adapter-maveo-v-0-0-x

## Changelog
### 0.1.0
* Zwei Betriebsmodi: Cloud (Cognito + Nymea-Tunnel) und LAN (direkt zur Box mit
  Push-Button-Auth). Region wählbar (EU/US). Cognito-Pool/Client-IDs und
  Cloud-Endpunkte aus der maveo-App 2.6.1 verifiziert (Ghidra-Decompile).
  Thing/Action-Discovery über Nymea, Push-basierte State-Updates, funktionierende
  Remote-Steuerung, Message-Buffering und exponentielles Reconnect-Backoff.
### 0.0.5
* (TA2k) update login keys
### 0.0.4
* (TA2k) fix status
### 0.0.1
* (TA2k) initial release

## Sentry

Dieser Adapter verwendet die Sentry-Bibliotheken, um Ausnahmen und Fehler
automatisch an den Entwickler zu melden. Details und Deaktivierung siehe
[Sentry-Plugin Documentation](https://github.com/ioBroker/plugin-sentry).

## License

MIT License

Copyright (c) 2021-2026 TA2k <tombox2020@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
