# Configuration format

`signatures.json` uses schema version 1:

```json
{
  "schema": 1,
  "module": "client.dll",
  "signatures": [
    {
      "name": "example",
      "pattern": "48 8B 0D ? ? ? ?",
      "kind": "rip_rel32",
      "required": true,
      "disp_offset": 3,
      "instruction_size": 7
    }
  ]
}
```

## Signature fields

| Field | Type | Meaning |
| --- | --- | --- |
| `name` | string | Unique output name. |
| `pattern` | string | Space-separated hexadecimal bytes; `?` or `??` is a wildcard. |
| `kind` | string | `match` returns the match RVA; `rip_rel32` resolves a signed rel32 target. |
| `required` | boolean | Defaults to `true`. A missing or ambiguous required signature fails the dump. |
| `disp_offset` | integer | Required for `rip_rel32`; byte offset of the signed displacement. |
| `instruction_size` | integer | Required for `rip_rel32`; full instruction size. |

Every configured pattern is scanned across readable committed regions of the
module. A signature is accepted only when exactly one match exists. This avoids
silently publishing the first result of an ambiguous pattern.
