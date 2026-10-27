"""Entrada compatível: ``streamlit run linhamestre_app.py``.

O código fica em ``src/linhamestre``; este arquivo apenas o carrega, para que o
comando histórico continue funcionando mesmo sem instalar o pacote.
"""

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from linhamestre.app import main  # noqa: E402

main()
