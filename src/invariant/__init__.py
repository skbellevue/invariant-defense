"""Invariant: a reference implementation of the Invariant Defense Model.

AI lets an attacker change the *form* of an attack cheaply (code, commands,
payloads regenerated on every run) but not its *requirements*:

    L1 Exposure   - it needs a way in
    L2 Model      - it must reach a language model
    L3 Behavior   - it must run on a host
    L4 Identity   - it must borrow privilege
    L5 Impact     - it must touch data

Each sub-package implements the controls for one invariant; ``response``
implements the machine-speed containment loop that ties them together.
"""

__version__ = "0.1.0"

LAYERS = {
    "L0": "Signatures & reputation (cheap filter)",
    "L1": "Exposure: needs a way in",
    "L2": "Model dependency: must reach an LLM",
    "L3": "Behavior: must run on a host",
    "L4": "Identity: must borrow privilege",
    "L5": "Impact: must touch data",
}
