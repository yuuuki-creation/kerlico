# CLI languages

Use `kerlico --lang en ...` for English or `kerlico --lang zh-CN ...` for Simplified Chinese. The global option can appear before or after the command.

Without an explicit option, the CLI reads the first nonempty value from `LC_ALL`, `LC_MESSAGES`, and `LANG`, in that order. A `zh` locale selects Simplified Chinese. Other locales and an unset environment select English.

```sh
kerlico --lang en --help
kerlico check --lang en -c examples/config-v2-minimal.json
kerlico help check --lang zh-CN
kerlico history --lang en --directory state/telemetry --kind flows --node entry --limit 20
```

Command and option names, configuration keys, JSON fields, and module identifiers remain stable across languages. Errors include a stable category such as `configuration.invalid` or `operation.timeout`.

The translation catalog includes static configuration, protocol, I/O, and service failure details for all 23 protocols, the shared runtime, and the history interface. VLESS Mux and XDRIVE background failures retain stable event codes and concrete causes in the selected language. Library callers select the language explicitly through `RuntimeOptions`; separate runtime instances can use different languages concurrently.

`history` exports usage totals, flow records, or bandwidth samples as JSON. Flow and bandwidth queries support cursors; projection filters are applied before pagination. Numeric validation details use the selected language. Queries open existing storage read-only, and `check` does not create it. Device ownership and WARP diagnostics are also included; automatic cross-process device sharing remains unfinished.

Unknown Chinese details remain visible with an explicit `[untranslated detail]` marker. The marker identifies a coverage gap in a new or external diagnostic; it never substitutes for a concrete English translation. Native operating system errors retain their original text and error code.

The [interface document](interfaces/localization.md) describes the explicit library API and the coverage check. Run all builds and checks on the dedicated overseas workers.
