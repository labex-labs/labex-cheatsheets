---
title: 'Vim Befehle Spickzettel | LabEx'
description: 'Vim Befehle Spickzettel für schnelles Texteditieren. Schnelle Referenz für Modi, Bewegung, Einfügen, Löschen, Kopieren, Einfügen, Suchen, Ersetzen, Fenster, Tabs, Buffer und Makros.'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Vim Befehle Spickzettel
</base-title>

<base-disclaimer>
<base-disclaimer-title>
Vim-Befehle im Terminal üben
</base-disclaimer-title>
<base-disclaimer-content>
Nutzen Sie diesen Vim Befehle Spickzettel als praktische Referenz zum Bearbeiten von Dateien in der Kommandozeile. Er behandelt Vim-Modi, Cursorbewegung, Einfügen und Ersetzen, visuelle Auswahl, Kopieren und Einfügen, Suchen und Ersetzen, Buffer, Fenster, Tabs, Makros, Marken, Register und Grundkonfiguration.
</base-disclaimer-content>
</base-disclaimer>

## Modes & Basic Control

### Open Vim: `vim file`

Open a file in Vim or create it if it does not exist.

```bash
# Open a file
vim notes.txt
# Open multiple files
vim file1.txt file2.txt
# Open file at a specific line
vim +25 app.py
# Open file at the first match
vim +/TODO app.py
```

### Switch Modes: `i`, `Esc`, `v`, `:`

Move between Vim's main editing modes.

```text
i      Insert before cursor
a      Insert after cursor
o      Open a new line below and insert
O      Open a new line above and insert
Esc    Return to normal mode
v      Start visual mode
V      Start visual line mode
Ctrl-v Start visual block mode
:      Start command-line mode
```

### Save and Quit: `:w`, `:q`

Write changes, quit Vim, or do both in one command.

```vim
:w       Save the current file
:q       Quit Vim
:wq      Save and quit
:x       Save and quit if changed
:q!      Quit without saving
:w file  Save as another file
```

## Cursor Movement

### Basic Movement: `h`, `j`, `k`, `l`

Move the cursor without leaving normal mode.

```text
h  Move left
j  Move down
k  Move up
l  Move right
```

### Word Movement: `w`, `b`, `e`

Jump by words and word endings.

```text
w   Move to the next word
W   Move to the next WORD separated by whitespace
b   Move back one word
B   Move back one WORD
e   Move to the end of the current or next word
ge  Move to the end of the previous word
```

### Line Movement: `0`, `^`, `$`

Move within the current line.

```text
0  Move to the beginning of the line
^  Move to the first non-blank character
$  Move to the end of the line
g_ Move to the last non-blank character
```

### File Movement: `gg`, `G`

Jump through the current file.

```text
gg       Go to the first line
G        Go to the last line
25G      Go to line 25
:25      Go to line 25
Ctrl-d   Move down half a page
Ctrl-u   Move up half a page
Ctrl-f   Move forward one page
Ctrl-b   Move backward one page
```

## Editing Commands

### Delete Text: `d`

Delete characters, words, lines, and ranges.

```text
x    Delete character under cursor
dw   Delete to the start of the next word
de   Delete to the end of the current word
dd   Delete the current line
2dd  Delete two lines
d$   Delete to the end of the line
d0   Delete to the beginning of the line
```

### Change Text: `c`

Delete text and enter insert mode.

```text
cw   Change word
ciw  Change inside word
cc   Change the whole line
c$   Change to the end of the line
ci"  Change inside double quotes
ci)  Change inside parentheses
```

### Copy and Paste: `y`, `p`

Yank text into a register and paste it.

```text
yy   Yank the current line
2yy  Yank two lines
yw   Yank word
y$   Yank to the end of the line
p    Paste after cursor or below line
P    Paste before cursor or above line
```

### Undo and Redo: `u`, `Ctrl-r`

Reverse or reapply edits.

```text
u       Undo the last change
U       Undo all latest changes on the current line
Ctrl-r  Redo the last undone change
.       Repeat the last change
```

## Search & Replace

### Search Text: `/pattern`

Find text in the current file.

```vim
/error       Search forward for error
?error       Search backward for error
n            Jump to the next match
N            Jump to the previous match
*            Search for the word under cursor
#            Search backward for the word under cursor
:set hlsearch     Highlight matches
:nohlsearch       Clear search highlighting
```

### Replace Text: `:s`

Substitute text in a line, range, or whole file.

```vim
:s/old/new/        Replace first match on current line
:s/old/new/g       Replace all matches on current line
:%s/old/new/g      Replace all matches in the file
:%s/old/new/gc     Replace all matches with confirmation
:10,20s/foo/bar/g  Replace between lines 10 and 20
```

## Visual Mode

### Select Text: `v`, `V`, `Ctrl-v`

Select characters, lines, or columns before applying commands.

```text
v       Select by character
V       Select whole lines
Ctrl-v  Select a block
o       Move to the other end of the selection
y       Yank selected text
d       Delete selected text
>       Indent selected text
<       Unindent selected text
```

### Visual Block Editing

Edit multiple lines at the same column.

```text
Ctrl-v  Start block selection
j/k     Extend selection down or up
I       Insert before selected block
A       Append after selected block
Esc     Apply edit to all selected lines
```

## Files, Buffers, Windows & Tabs

### File Commands

Open, reload, and write files.

```vim
:e file.txt      Open another file
:e!              Reload current file and discard changes
:r file.txt      Read another file into current buffer
:w               Save current file
:saveas new.txt  Save current file as new.txt
```

### Buffer Commands

Switch between open files.

```vim
:ls       List buffers
:bnext    Go to next buffer
:bprev    Go to previous buffer
:b 3      Go to buffer 3
:bd       Delete current buffer
```

### Window Commands

Split the editor into multiple windows.

```vim
:split file.txt   Horizontal split
:vsplit file.txt  Vertical split
Ctrl-w h          Move to left window
Ctrl-w j          Move to lower window
Ctrl-w k          Move to upper window
Ctrl-w l          Move to right window
Ctrl-w =          Make windows equal size
```

### Tab Commands

Use tabs for groups of windows.

```vim
:tabnew file.txt  Open file in a new tab
:tabnext          Go to next tab
:tabprev          Go to previous tab
:tabclose         Close current tab
gt                Go to next tab
gT                Go to previous tab
```

## Marks, Registers & Macros

### Marks: `m`

Save a position and jump back to it.

```text
ma   Set mark a
'a   Jump to the line of mark a
`a   Jump to the exact position of mark a
:marks  List marks
```

### Registers: `"`

Use named storage for yanks, deletes, and pastes.

```text
"ayy   Yank current line into register a
"ap    Paste from register a
":p    Paste the last command-line command
"0p    Paste the last yanked text
:reg   List registers
```

### Macros: `q`

Record and replay repeated edits.

```text
qa   Start recording macro into register a
q    Stop recording
@a   Run macro a
@@   Repeat the last macro
5@a  Run macro a five times
```

## Configuration Commands

### Useful Settings

Enable common Vim settings from command mode or `.vimrc`.

```vim
:set number
:set relativenumber
:set expandtab
:set tabstop=2
:set shiftwidth=2
:set ignorecase
:set smartcase
:set wrap
:set nowrap
:syntax on
```

### Edit Vim Configuration

Open and reload your Vim config.

```vim
:e ~/.vimrc
:source ~/.vimrc
```

## Relevant Links

- <router-link to="/shell">Bash Commands Cheat Sheet</router-link>
- <router-link to="/linux">Ubuntu Commands Cheat Sheet</router-link>
- <router-link to="/git">Git Commands Cheat Sheet</router-link>
- <router-link to="/devops">DevOps Cheat Sheet</router-link>
