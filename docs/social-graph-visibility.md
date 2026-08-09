# Social graph and visibility

`friend` is a direct social connection. `sponsor-trust` records externally meaningful provenance without becoming a friendship edge. Neither relationship proves the other, and friendship does not prove covenant trust.

Visibility is a pure decision over separately supplied access status and graph context:

| Viewer status | Self | Direct friend | Friend of friend | Unrelated |
| --- | --- | --- | --- | --- |
| Limited | visible | visible | restricted | restricted |
| Full / Operator | visible | visible | visible | restricted |

Unknown status, context, or policy denies by default. Graph traversal never upgrades covenant status.
