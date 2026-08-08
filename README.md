# ios-dumper

External, read-only x64 offset dumper for IOSoccer. It scans signatures in `client.dll`, discovers the available Source `VClient` interface, walks its RecvTables, and exports deterministic JSON offsets without injection or process memory writes.

## Usage

1. Download the latest Windows x64 artifact from **GitHub Actions**, or build the project in `Release|x64`.
2. Keep `iosdumper.exe` and `signatures.json` in the same directory.
3. Start IOSoccer.
4. Run `iosdumper.exe`.

You can optionally specify the game process ID:

```text
iosdumper.exe <PID>
```

Generated offsets are written to `out/iosoccer_offsets.json`. Runtime information and errors are written to `out/diagnostics.json`.
