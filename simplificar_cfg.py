
# - Valida sintaxis de la CFG con REGEX
# - Calcula anulables
# - Elimina ε-producciones preservando el lenguaje (agrega S' si S es anulable)
# - Muestra los pasos y la gramática resultante

import re
import sys
from collections import defaultdict
from itertools import product
from typing import Dict, Set, List, Tuple

FLECHA = r'(?:->|→)'
EPS_SET = {'ε', 'ϵ'}

ALT = r'(?:[A-Za-z0-9]+|[εϵ])'
REGEX_LINEA = re.compile(rf'^[A-Z]\s*{FLECHA}\s*{ALT}(?:\s*\|\s*{ALT})*\s*$')

def normaliza_flecha(linea: str) -> str:
    return linea.replace('→', '->')

def parse_linea(linea: str) -> Tuple[str, List[str]]:
    """
    Parsea 'A -> α | β | ε' y devuelve (LHS, [rhs1, rhs2,...]).
    Cada rhs es 'ε' o una cadena [A-Za-z0-9]+ (sin espacios).
    """
    linea = normaliza_flecha(linea.strip())
    if not REGEX_LINEA.match(linea):
        raise ValueError(f"Línea inválida: {linea}")
    lhs, rhs = linea.split('->', 1)
    lhs = lhs.strip()
    alts = [alt.strip() for alt in rhs.split('|')]
    alts = ['ε' if alt in EPS_SET else alt for alt in alts]
    return lhs, alts

def carga_gramatica(path: str):
    """
    Lee el archivo y devuelve:
      N: set de no terminales (A..Z)
      T: set de terminales (a..z, 0..9)
      P: dict LHS -> set de strings (cada cuerpo es 'ε' o [A-Za-z0-9]+)
      S: símbolo inicial (primer LHS leído)
    """
    P: Dict[str, Set[str]] = defaultdict(set)
    N: Set[str] = set()
    T: Set[str] = set()
    S = None
    with open(path, encoding='utf-8') as f:
        for ln, raw in enumerate(f, 1):
            raw = raw.strip()
            if not raw or raw.startswith('#'):
                continue
            lhs, alts = parse_linea(raw)
            if S is None:
                S = lhs
            N.add(lhs)
            for alt in alts:
                P[lhs].add(alt)
                if alt != 'ε':
                    for ch in alt:
                        if 'A' <= ch <= 'Z':
                            N.add(ch)
                        elif ch.islower() or ch.isdigit():
                            T.add(ch)
                        else:
                            pass
    if S is None:
        raise ValueError("Archivo vacío o sin producciones válidas.")
    return N, T, P, S

def anulables(N: Set[str], P: Dict[str, Set[str]]) -> Set[str]:
    """
    Calcula el conjunto de no terminales anulables (que derivan ε).
    Método clásico por fijación.
    """
    nullable = set(X for X in N if 'ε' in P.get(X, set()))
    changed = True
    while changed:
        changed = False
        for A in N:
            if A in nullable:
                continue
            for alpha in P.get(A, set()):
                if alpha == 'ε':
                    nullable.add(A)
                    changed = True
                    break
                if all(('A' <= c <= 'Z') and (c in nullable) for c in alpha):
                    nullable.add(A)
                    changed = True
                    break
    return nullable

def genera_variantes(alpha: str, nullable_set: Set[str]) -> Set[str]:
    """
    Genera todas las variantes de alpha borrando opcionalmente las ocurrencias
    de no terminales anulables. Si alpha == 'ε' -> {'ε'}.
    Si se borra todo, retorna 'ε'.
    """
    if alpha == 'ε':
        return {'ε'}
    pos = [i for i, c in enumerate(alpha) if ('A' <= c <= 'Z') and (c in nullable_set)]
    if not pos:
        return {alpha}
    variants = set()
    for keep_mask in product([0, 1], repeat=len(pos)):
        keep_idx = {pos[i] for i, b in enumerate(keep_mask) if b == 1}
        s_chars = []
        for i, c in enumerate(alpha):
            if ('A' <= c <= 'Z') and (c in nullable_set) and (i not in keep_idx):
                continue
            s_chars.append(c)
        variants.add(''.join(s_chars) if s_chars else 'ε')
    return variants

def elimina_epsilon(N: Set[str], T: Set[str], P: Dict[str, Set[str]], S: str,
                    conservar_epsilon_inicio: bool = True):
    """
    Elimina ε-producciones. Si S es anulable y conservar_epsilon_inicio=True,
    crea S' -> S | ε para preservar el lenguaje.
    Retorna (N', T, P', S').
    """
    print("\n>>> Eliminación de ε-producciones")
    nullable = anulables(N, P)
    print("Anulables:", sorted(nullable))

    S0 = S
    newN = set(N)
    newP: Dict[str, Set[str]] = {A: set(rhss) for A, rhss in P.items()}

    # Si S anulable y queremos preservar ε, introducimos S'
    if (S in nullable) and conservar_epsilon_inicio:
        S0 = S + "'"
        while S0 in newN:
            S0 += "'"
        newN.add(S0)
        newP[S0] = {'ε', S}

    # Construir nuevas producciones sin ε (excepto posible S0->ε)
    P_out: Dict[str, Set[str]] = {A: set() for A in newN}
    for A in newN:
        for alpha in newP.get(A, set()):
            if alpha == 'ε':
                if A == S0 and conservar_epsilon_inicio:
                    P_out[A].add('ε')
                continue
            for beta in genera_variantes(alpha, nullable):
                if beta != 'ε':
                    P_out[A].add(beta)
                elif A == S0 and conservar_epsilon_inicio:
                    P_out[A].add('ε')

    return newN, T, P_out, S0

def imprime_gramatica(N: Set[str], T: Set[str], P: Dict[str, Set[str]], S: str, titulo: str = ""):
    if titulo:
        print(f"\n--- {titulo} ---")
    print(f"(Inicio: {S})")
    for A in sorted(N):
        rhss = P.get(A, set())
        if not rhss:
            continue
        rhs_txt = ' | '.join(sorted(rhss))
        print(f"{A} -> {rhs_txt}")

def main():
    if len(sys.argv) < 2:
        print("Uso: python simplificar_cfg.py cfg1.txt [cfg2.txt ...]")
        sys.exit(1)

    for path in sys.argv[1:]:
        print("\n" + "="*70)
        print(f"Procesando archivo: {path}")
        print("="*70)
        try:
            N, T, P, S = carga_gramatica(path)
        except Exception as e:
            print(f"Error al cargar/validar: {e}")
            continue

        imprime_gramatica(N, T, P, S, "Gramática cargada")

        N2, T2, P2, S2 = elimina_epsilon(N, T, P, S, conservar_epsilon_inicio=True)
        imprime_gramatica(N2, T2, P2, S2, "Sin ε (conservando ε solo en S' si aplica)")

if __name__ == "__main__":
    main()
