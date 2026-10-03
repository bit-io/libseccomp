# libseccomp

Natywny, **w 100% napisany w H#**, odpowiednik crate'a `libseccomp` z Rusta:
budowanie i instalowanie filtrów **seccomp-bpf** bez linkowania z prawdziwym
`libseccomp.so`, bez pliku C/Rust-shim kompilowanego obok, bez
`extern static [rust, "..."]` — jedyna granica FFI to `extern static [c]`
do `prctl`/`syscall`/`ioctl`/`close` z libc (`src/ffi.h#`), bo operacje na
seccomp są operacjami jądra i nie da się ich wykonać w czystej przestrzeni
użytkownika żadnym innym sposobem.

Program BPF (classic BPF, nie eBPF) jest składany ręcznie, instrukcja po
instrukcji, w H#, i pakowany bit-po-bicie do pamięci przy pomocy
wbudowanych w język prymitywów `@pointers`/`arc_alloc`/`ptr_write_*` —
zobacz nagłówkowy komentarz w `src/bpf.h#` po pełne wyjaśnienie, dlaczego
ani `bytes`, ani `string` nie nadają się do trzymania tego bufora.

## Instalacja

```bash
cd twoj-projekt
bit add libseccomp
```

lub w `Bit.hk`:

```
[dependencies]
-> libseccomp => newest
```

a w kodzie: `use "bit -> libseccomp"`.

## Struktura modułów

Kod źródłowy jest podzielony na kilka plików w `src/`, połączonych przez
`mod` w `src/lib.h#` (punkt wejścia biblioteki — `bit` znajduje go sam jako
`src/lib.h#`). W H# każdy `mod X` nadaje funkcjom i strukturom z pliku
`X.h#` prefiks `X_`, więc z zewnątrz funkcję woła się przez nazwę **modułu**,
w którym mieszka: `rules::allow(...)`, `install::install(...)`,
a typ jako `rules::Rule`. Stałe (`ACTION_*`, `ARCH_*`, `EPERM`, …) nie są
prefiksowane — używa się ich po prostu po nazwie. Wywołania między plikami
wewnątrz biblioteki muszą być zapisane tak samo (np. `bpf::pack_instr(...)`
w `ir.h#`) — niekwalifikowana nazwa z innego pliku kończy się błędem
`codegen: undefined fn`:

| Plik | Zawartość |
|---|---|
| `consts.h#` | stałe `prctl`/`seccomp(2)`/akcje/architektury/ioctl/opcode'y BPF |
| `errno.h#` | mapowanie nazwa↔numer errno (`deny_errno`, `action_errno`) |
| `ir.h#` | pośrednia reprezentacja instrukcji + łatanie skoków (dla komparatorów i bsearch) |
| `bpf.h#` | `pack_instr` + `build_program` (liniowy / multi-arch / bsearch) |
| `rules.h#` | typ `Rule`, buildery `allow`/`deny_*`, `allow_baseline`, `validate_rules` |
| `comparators.h#` | `ArgCond`/`CondRule` — filtrowanie po wartościach argumentów |
| `syscalls_x86_64.h#` | tabela syscalli x86_64 |
| `syscalls_aarch64.h#` | tabela syscalli aarch64 |
| `syscalls.h#` | dyspozytor `number()`/`number_for_arch()` |
| `export.h#` | `export_hex`/`import_hex` (serializacja), `export_pfc` (disasm) |
| `ffi.h#` | jedyny blok `extern static [c]` w całej bibliotece |
| `install.h#` | instalacja gotowego programu przez `prctl` |
| `notify.h#` | wsparcie dla `SECCOMP_RET_USER_NOTIF` |

## Szybki start

```hsharp
use "bit -> libseccomp"

fn main() is
    let mut rules: [rules::Rule] = rules::new_rules()
    rules = rules::allow_baseline(rules)     ;; read/write/mmap/exit/...
    rules = rules::allow(rules, "openat")
    rules = rules::deny_errno(rules, "ptrace", EPERM)

    let warnings: [string] = rules::validate_rules(rules)
    ;; (opcjonalnie: wypisz `warnings`, jeśli niepuste — literówki i
    ;; konflikty reguł, nigdy fatalne same w sobie)

    let ok: bool = install::install(rules, ACTION_KILL_PROCESS)
    if !ok is
        write("install failed, errno=" + to_string(install::last_errno()))
    end
end
```

**Kompilacja wyłącznie przez backend LLVM:**

```bash
h# compile src/main.h# --release -o app
```

`h# preview` (interpreter) **nie** obsługują `extern`,
`arc_alloc` ani `ptr_*` — działa wyłącznie logika czysta (`bpf.h#`,
`rules.h#`, `comparators.h#`'s encoding, obie tabele syscalli, `errno.h#`,
`export.h#`), którą pokrywa `src/lib_test.h#` uruchamiane przez
`bit test`. `install.h#`/`notify.h#` (i `ffi.h#`, z którego korzystają)
wymagają realnie skompilowanej binarki.

## API

### Budowanie listy reguł (`rules.h#`)

| Funkcja | Opis |
|---|---|
| `new_rules() -> [Rule]` | pusta lista reguł |
| `allow(rules, name) -> [Rule]` | dopisz `ALLOW` dla syscalla (tabela x86_64) |
| `allow_arch(rules, name, arch) -> [Rule]` | jak wyżej, z tabelą wybranej architektury |
| `allow_nr(rules, nr) -> [Rule]` | jak `allow`, po surowym numerze |
| `deny_errno(rules, name, err) -> [Rule]` | zwróć `err` zamiast wykonać syscall |
| `deny_errno_arch(rules, name, err, arch) -> [Rule]` | jak wyżej, z tabelą wybranej architektury |
| `deny_errno_nr(rules, nr, err) -> [Rule]` | jak wyżej, po numerze |
| `deny_kill(rules, name) -> [Rule]` | zabij proces przy tym syscallu |
| `deny_trap(rules, name) -> [Rule]` | wyślij `SIGSYS` (do przechwycenia) |
| `deny_log(rules, name) -> [Rule]` | wpuść, ale zaloguj (audyt/dmesg) |
| `allow_baseline(rules) -> [Rule]` | gotowy zestaw dla zwykłego programu CLI |
| `validate_rules(rules) -> [string]` | ostrzeżenia: nierozwiązane nazwy, konflikty, duplikaty |
| `dedupe_rules(rules) -> [Rule]` | usuń duplikaty po `nr` (zachowuje pierwsze wystąpienie) |

Nieznana nazwa syscalla (literówka) **nigdy** nie zamienia się po cichu w
"zezwól na wszystko" — `number()` zwraca `-1`, a każdy budowniczy po prostu
nic wtedy nie dopisuje. `validate_rules` pozwala to wykryć jawnie zamiast
odkrywać dopiero w czasie działania.

### Komparatory argumentów (`comparators.h#`)

Odpowiednik `ScmpArgCompare`/`add_rule_conditional` z Rustowego
`libseccomp` — filtrowanie nie tylko po numerze syscalla, ale i po
wartości jego argumentów:

```hsharp
;; openat(dirfd, path, flags, mode) — zezwól tylko na odczyt
let conds: [comparators::ArgCond] = [comparators::masked_eq(2, 0x3, 0)]  ;; (flags & O_ACCMODE) == O_RDONLY
let mut rules: [comparators::CondRule] = []
rules.push(comparators::cond_rule(syscalls::number("openat"), ACTION_ALLOW, conds))
rules.push(comparators::cond_rule(syscalls::number("openat"), consts::action_errno(EACCES), []))
install::install_cond(rules, ACTION_KILL_PROCESS)
```

| Funkcja | Warunek |
|---|---|
| `eq(idx, val)` | `args[idx] == val` — **pełna precyzja 64-bit** |
| `ne(idx, val)` | `args[idx] != val` — dolne 32 bity |
| `lt`/`le`/`gt`/`ge(idx, val)` | porównanie — dolne 32 bity |
| `masked_eq(idx, mask, val)` | `(args[idx] & mask) == val` — dolne 32 bity |

Tylko `eq` sprawdza pełne 64 bity `seccomp_data.args[i]` (osobne
porównanie górnego i dolnego słowa); reszta operuje na dolnych 32 bitach,
co pokrywa zdecydowaną większość realnych przypadków (fd, flagi, małe
rozmiary) bez komplikacji pełnego trójstronnego porównania 64-bit.
`rule_to_cond(rule)` podnosi zwykłą `Rule` do `CondRule` bez warunków, żeby
mieszać je w jednej liście `[CondRule]` z prawdziwymi regułami warunkowymi.

### Instalacja filtra (`install.h#`)

| Funkcja | Opis |
|---|---|
| `install(rules, default_action) -> bool` | dla `ARCH_X86_64`, schemat liniowy |
| `install_arch(rules, default_action, arch) -> bool` | wybrana architektura |
| `install_multi_arch(rules, default_action, arches) -> bool` | jeden filtr dla kilku ABI naraz |
| `install_bsearch(rules, default_action, arch) -> bool` | dyspozytor binarny O(log n) zamiast liniowego |
| `install_cond(rules, default_action) -> bool` | j.w., dla `[CondRule]` |
| `install_cond_arch(rules, default_action, arch) -> bool` | j.w. + architektura |
| `last_errno() -> int` | `errno` po nieudanej instalacji |
| `seccomp_mode() -> int` | 0=brak, 1=strict, 2=filter (już aktywny) |

Filtr, raz zainstalowany, może być w tym procesie tylko **zaostrzany** —
tak działa jądro. Druga instalacja dokłada kolejny filtr (logiczny AND),
nie zastępuje poprzedniego.

`install_bsearch` sortuje reguły i dysponuje je drzewem porównań
`BPF_JGE` zamiast liniowego łańcucha — O(log n) zamiast O(n) porównań na
syscall, opłacalne od kilkudziesięciu–kilkuset reguł wzwyż. Domyślny,
liniowy schemat (`install`/`install_arch`) zostaje domyślny celowo: każdy
skok w nim ma stałą długość 0 lub 1, więc nigdy nie zbliża się do limitu
255 instrukcji klasycznego BPF, niezależnie od liczby reguł — jest
prościej zweryfikować go "na oko".

### Powiadomienia użytkownika — `SECCOMP_RET_USER_NOTIF` (`notify.h#`)

Zamiast sztywnego werdyktu z programu BPF, wybrana reguła może oddać
decyzję procesowi nadzorującemu w czasie rzeczywistym — mechanizm, którego
używają np. runtime'y kontenerów do selektywnego zezwalania na syscalle
normalnie wymagające capability, jakich sandboksowany proces mieć nie
powinien.

```hsharp
let fd: int = notify::install_notify(rules, ACTION_KILL_PROCESS, ARCH_X86_64)
let n: notify::Notif = notify::notif_receive(fd)      ;; blokuje do następnego zdarzenia
;; n.nr, n.pid, n.args[0..6] — zdecyduj...
if notify::notif_id_valid(fd, n.id) is
    notify::notif_respond(fd, n.id, 0, 0, 0)           ;; zezwól, syscall zwraca 0
end
```

| Funkcja | Opis |
|---|---|
| `install_notify(rules, default_action, arch) -> int` | zwraca fd powiadomień (lub wartość ujemną) |
| `notif_receive(fd) -> Notif` | czeka na kolejne zdarzenie |
| `notif_respond(fd, id, val, error, flags) -> bool` | odpowiedz na zdarzenie |
| `notif_id_valid(fd, id) -> bool` | sprawdź, czy `id` wciąż aktualne |
| `close_notify(fd) -> bool` | zamknij fd powiadomień |

Oznacz regułę do przekazania nadzorcy przez `ACTION_USER_NOTIF` zamiast
zwykłej akcji (`Rule { nr: ..., action: ACTION_USER_NOTIF }`).

### Eksport / import (`export.h#`)

| Funkcja | Opis |
|---|---|
| `export_hex(prog) -> string` | zserializuj zbudowany program do stringa (do cache'owania) |
| `import_hex(s) -> [int]` | odwrotność `export_hex` |
| `export_pfc(prog) -> string` | czytelny dla człowieka disasm (do debugowania) |

Bez operacji na plikach — persystencja to jedna linijka
`use "std -> fs" from "fs"` + `fs::write(...)` u wywołującego, nie
narzucona zależność.

### Errno (`errno.h#`)

Stałe (`EPERM`, `ENOENT`, `EACCES`, `EINVAL`, `ENOSYS`, ...) plus pełne
`errno_number(name) -> int` / `errno_name(num) -> string` (>130 wpisów,
standardowa numeracja Linuksa, niezależna od architektury).

### Akcje (`SECCOMP_RET_*`)

`ACTION_ALLOW`, `ACTION_KILL_PROCESS`, `ACTION_KILL_THREAD`/`ACTION_KILL`,
`ACTION_TRAP`, `ACTION_LOG`, `ACTION_TRACE`, `ACTION_USER_NOTIF`, oraz
`action_errno(err)` / `action_trace(msg)` do budowania wariantów z
payloadem.

### Architektury (`AUDIT_ARCH_*`)

`ARCH_X86_64` (domyślna), `ARCH_AARCH64`, `ARCH_I386`, `ARCH_ARM`.

### Tabele syscalli

`number(name)` / `number_x86_64(name)` — x86_64, >320 wpisów.
`number_aarch64(name)` — aarch64 (tabela generyczna, inna numeracja niż
x86_64 — to nie jest literówka, to dwa różne ABI). `number_for_arch(name,
arch)` — dyspozytor. Czego zabraknie, można nadal filtrować przez
`allow_nr`/`deny_errno_nr` po surowym numerze.

## Przykłady

- `examples/basic_sandbox.h#` — statyczna allow-lista + `KILL_PROCESS`.
- `examples/network_sandbox.h#` — allow-lista + gniazda wychodzące, jawny
  `EPERM` na `bind`/`listen`/`accept*`, tryb `LOG` do nauki wymagań
  programu przed przejściem na `KILL_PROCESS`.
- `examples/arg_comparator_sandbox.h#` — `openat` dozwolony tylko do
  odczytu (komparator na fladze `O_ACCMODE`).
- `examples/notify_sandbox.h#` — `mount()` oddane do decyzji nadzorcy
  przez `SECCOMP_RET_USER_NOTIF`.

## Dlaczego nie `extern static [rust, "..."]`

Rozważane, ale niepotrzebne: nie ma tu żadnej statycznej biblioteki Rust
do zlinkowania `--whole-archive`, bo cała logika (enkoder BPF, tabele
syscalli, komparatory, buildery reguł) jest czystym H#. Jedyna prawdziwa
granica FFI (`ffi.h#`) to cztery zwykłe funkcje libc — stąd
`extern static [c]`, dokładnie tak jak `malloc`/`free` w testach
kompilatora H# (`tests/compiler/unsafe_arena_kinds_test.h#`).

## Ograniczenia

- Tylko Linux (seccomp-bpf to mechanizm jądra Linuksa).
- `install*`/`notify*` wymagają backendu LLVM (patrz wyżej).
- Komparatory poza `eq` operują na dolnych 32 bitach argumentu (patrz
  `comparators.h#`) — w praktyce wystarcza to niemal zawsze, ale nie jest
  to pełna precyzja 64-bit jak w prawdziwym `libseccomp`.
- Brak wsparcia dla starych, zmultipleksowanych syscalli (`socketcall`,
  `ipc` na i386) — dotyczy głównie starszych architektur 32-bitowych.
- Tabela `syscalls_aarch64.h#` była zestawiona ręcznie z publicznej
  numeracji `asm-generic/unistd.h` — w przeciwieństwie do dekady
  stabilnej tabeli x86_64, warto zweryfikować ją względem nagłówków
  konkretnego jądra przed użyciem produkcyjnym.

## Licencja

MIT — zobacz `LICENSE`.
