# Frozen blind oracle provenance

The files under `source/` are byte-for-byte copies of the Package-A result
from the offline Ed301-EdDSA blind experiment of 2026-08-24. They remain an
immutable evidence artifact; fixes belong in `oracle_adapter.py`, never in
the copied source.

## Bound experiment

- freeze commit: `0c48294893e9b7ec46109de51c3a04829befb39f`
- freeze tree: `860399c5e2cc9f3e682daed22034898b432440c2`
- original outer Package-A transport:
  `e2e3df24c1c2eb31495227703f06d4b266a046777d1c7b295b69c6c7327ebafd`
- authoritative inner Package-A ZIP:
  `d59425e220b1561fb542a3f016e69df32d210e94ee7b3fce38466967d8da864e`
- Package-A implementation:
  `2364f483696c81dba7b81f0cc37f4037983a2c6795c204586e6c09f6a3669bf3`
- Package-A ambiguity report:
  `961d2d9c32b83726163cbd652926b4df12121dbc837bb9e681bdea7be06948c5`
- Package-A README:
  `845d77f16001ed7774ce525e2a717878451b81079969e84be210afc3d3be01bd`
- Package-A manifest:
  `bda1c016894a55efb94fab1df5969b3540fc797bd9121214853d6a555a208fca`
- sealed Package B:
  `c4f487918cb7efea47753136790446dbedd2ef0cc3a9bd655bd43160c00b32c5`
- final result: 109/109 normative assertions passed without modifying A
- final judge report:
  `19db4e4d9211d14ee74293b0143abc13fd0969ee0a778acf3000bfb88119cb87`

The frozen implementation is variable-time test code and must never process
real secrets. Its direct module API is unsupported. The adapter exposes only
deterministic byte-level operations, rejects mutable or non-byte inputs, and
hides all raw affine point helpers.

The imported result and the project-owned adapter are distributed as part of
this repository under its Apache-2.0 license. This provenance note does not
alter the hashes or claims of the original sealed experiment.
