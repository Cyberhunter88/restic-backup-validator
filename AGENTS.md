# Projektregeln

- Jede Funktion wird auf einem eigenen Feature-Branch entwickelt und nur per Pull Request in `main` integriert.
- Releases und veröffentlichte Container-Images werden ausschließlich durch den Eigentümer über den manuellen GitHub-Actions-Workflow ausgelöst.
- Zugangsdaten, private Infrastrukturdetails, Datenbanken und echte Konfigurationsdateien gehören nicht in Git. Beispiele verwenden nur offensichtliche Platzhalter.
- Vor jedem Push den Secret-Scan für alle ausgehenden Commits ausführen. Scanner-Funde niemals mit ihrem Wert ausgeben.
