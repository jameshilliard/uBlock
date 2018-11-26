;;
;; uBlock Origin - a browser extension to block requests.
;; Copyright (C) 2018-present Raymond Hill
;;
;; This program is free software: you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.
;;
;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.
;;
;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see {http://www.gnu.org/licenses/}.
;;
;; Home: https://github.com/gorhill/uBlock
;; File: hntrie.wat
;; Description: WebAssembly code used by src/js/hntrie.js
;; How to compile: See README.md in this directory.

(module
;;
;; module start
;;

(memory (import "imports" "memory") 1)

;;
;; Public functions
;;

;;
;; unsigned int matches(offset)
;;
;; Test whether the currently set needle matches the trie at specified offset.
;;
;; Memory layout, byte offset:
;;   0-254: encoded needle (ASCII)
;; 255    : needle length
;; 256    : offset to start of character data section
;; 260-   : trie data section
;;
(func (export "matches")
    (param $icell i32)          ;; offset to root cell of the trie
    (result i32)                ;; result = match index, -1 = miss
    (local $char0 i32)          ;; offset to first character data
    (local $ineedle i32)        ;; current needle offset
    (local $c i32)
    (local $v i32)
    (local $n i32)
    (local $i0 i32)
    (local $i1 i32)
    i32.const 264               ;; start of char section is stored at addr 264
    i32.load
    set_local $char0
    ;; $icell is an index into an array of 32-bit values
    get_local $icell
    i32.const 2
    i32.shl
    set_local $icell
    ;; let ineedle = this.buf[255];
    i32.const 255               ;; addr of needle is stored at addr 255
    i32.load8_u
    set_local $ineedle
    ;; for (;;) {
    block $noSegment loop $nextSegment
        ;; if ( ineedle === 0 ) { return -1; }
        get_local $ineedle
        i32.eqz
        if
            i32.const -1
            return
        end
        ;; ineedle -= 1;
        get_local $ineedle
        i32.const -1
        i32.add
        tee_local $ineedle
        ;; let c = this.buf[ineedle];
        i32.load8_u
        set_local $c
        ;; for (;;) {
        block $foundSegment loop $findSegment
            ;; v = this.buf32[icell+2];
            get_local $icell
            i32.load offset=8
            tee_local $v
            ;; i0 = this.char0 + (v & 0x00FFFFFF);
            i32.const 0x00FFFFFF
            i32.and
            get_local $char0
            i32.add
            tee_local $i0
            ;; if ( this.buf[i0] === c ) { break; }
            i32.load8_u
            get_local $c
            i32.eq
            br_if $foundSegment
            ;; icell = this.buf32[icell+0];
            get_local $icell
            i32.load
            i32.const 2
            i32.shl
            tee_local $icell
            i32.eqz
            if
                i32.const -1
                return
            end
            br 0
        end end
        ;; let n = v >>> 24;
        get_local $v
        i32.const 24
        i32.shr_u
        tee_local $n
        ;; if ( n > 1 ) {
        i32.const 1
        i32.gt_u
        if
            ;; n -= 1;
            get_local $n
            i32.const -1
            i32.add
            tee_local $n
            ;; if ( n > ineedle ) { return -1; }
            get_local $ineedle
            i32.gt_u
            if
                i32.const -1
                return
            end
            get_local $i0
            i32.const 1
            i32.add
            tee_local $i0
            ;; const i1 = i0 + n;
            get_local $n
            i32.add
            set_local $i1
            ;; do {
            loop
                ;; ineedle -= 1;
                get_local $ineedle
                i32.const -1
                i32.add
                tee_local $ineedle
                ;; if ( this.buf[i0] !== this.buf[ineedle] ) { return -1; }
                i32.load8_u
                get_local $i0
                i32.load8_u
                i32.ne
                if
                    i32.const -1
                    return
                end
                ;; i0 += 1;
                get_local $i0
                i32.const 1
                i32.add
                tee_local $i0
                ;; } while ( i0 < i1 );
                get_local $i1
                i32.lt_u
                br_if 0
            end
        end
        ;; icell = this.buf32[icell+1];
        get_local $icell
        i32.load offset=4
        i32.const 2
        i32.shl
        tee_local $icell
        ;; if ( icell === 0 ) { break; }
        i32.eqz
        br_if $noSegment
        ;; if ( this.buf32[icell+2] === 0 ) {
        get_local $icell
        i32.load
        i32.eqz
        if
            ;; if ( ineedle === 0 || this.buf[ineedle-1] === 0x2E ) {
            ;;     return ineedle;
            ;; }
            get_local $ineedle
            i32.eqz
            if
                i32.const 0
                return
            end
            get_local $ineedle
            i32.const -1
            i32.add
            i32.load8_u
            i32.const 0x2E
            i32.eq
            if
                get_local $ineedle
                return
            end
            ;; icell = this.buf32[icell+1];
            get_local $icell
            i32.load offset=4
            i32.const 2
            i32.shl
            set_local $icell
        end
        br 0
    end end
    ;; return ineedle === 0 || this.buf[ineedle-1] === 0x2E ? ineedle : -1;
    get_local $ineedle
    i32.eqz
    if
        i32.const 0
        return
    end
    get_local $ineedle
    i32.const -1
    i32.add
    i32.load8_u
    i32.const 0x2E
    i32.eq
    if
        get_local $ineedle
        return
    end
    i32.const -1
)

;;
;; module end
;;
)
