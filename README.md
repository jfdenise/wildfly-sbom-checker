# wildfly-sbom-checker

Check a WildFly installation that contains a generated SBOM and display findings.

```
java -jar target/wildfly-sbom-checker-1.0.0-SNAPSHOT.jar <install-root>
```

Not that if WildFly channels are configured, the check is also applied against the generated channel manifest.

