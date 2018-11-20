/*******************************************************************************

    uBlock Origin - a browser extension to block requests.
    Copyright (C) 2018-present Raymond Hill

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see {http://www.gnu.org/licenses/}.

    Home: https://github.com/gorhill/uBlock
*/

/* globals WebAssembly */
/* exported hnBigTrieManager */

'use strict';

/*******************************************************************************

  HNBigTrie is a flavor of trie modified from the original HNTrie code, found
  in ./hntrie.js -- which can also be used for reference.

  HNBigTrie has the following features:

  - Designed to hold large number of hostnames
  - Hostnames can be added at any time (instead of all at once)
    - This means pre-sorting is not a requirement (unlike HNTrie)
  - The trie is always compact
    - This means there is no need for a `vacuum` method (unlike HNTrie)
  - It can return the exact hostname which caused the match

  It's primary purpose is to replace the use of Set() has a mean to hold
  large number of hostnames (ex. FilterHostnameDict in static filtering
  engine).

*/

const hnBigTrieManager = {
    buf: new Uint8Array(131072),
    buf32: null,
    trie0: 256,
    trie1: 256,
    char0: 65536,
    char1: 65536,
    id: 0,
    needle: '',
    wasmLoading: null,
    wasmMemory: null,
    segments: new Map(),
    savedByteCount: 0,

    reset: function() {
        if ( this.wasmMemory === null && this.buf.byteLength > 131072 ) {
            this.buf = new Uint8Array(131072);
            this.buf32 = null;
        } else {
            this.buf.fill(0);
        }
        this.trie0 = this.trie1 = 256;
        this.char0 = this.char1 = this.buf.length >>> 1;
        this.segments = new Map();
        this.needle = '';
        this.id += 1;
        this.savedByteCount = 0;
    },

    readyToUse: function() {
        return this.wasmLoading instanceof Promise
            ? this.wasmLoading
            : Promise.resolve();
    },

    setNeedle: function(needle) {
        if ( needle !== this.needle ) {
            const buf = this.buf;
            let i = needle.length;
            if ( i > 254 ) { i = 254; }
            buf[255] = i;
            while ( i-- ) {
                buf[i] = needle.charCodeAt(i);
            }
            this.needle = needle;
        }
        return this;
    },

    matchesJS: function(iroot) {
        let ineedle = this.buf[255];
        if ( ineedle === 0 ) { return -1; }
        let icell = iroot;
        do {
            const v = this.buf32[icell+2];
            let slen = v >>> 24;
            let i0 = this.char0 + (v & 0x00FFFFFF);
            // if first character does not match, move to next descendant
            if ( this.buf[i0] !== this.buf[ineedle-1] ) {
                icell = this.buf32[icell+0];
                continue;
            }
            ineedle -= 1;
            // all characters in segment must match
            if ( slen > 1 ) {
                slen -= 1;
                if ( slen > ineedle ) { return -1; }
                i0 += 1;
                const i1 = i0 + slen;
                do {
                    ineedle -= 1;
                    if ( this.buf[i0] !== this.buf[ineedle] ) { return -1; }
                    i0 += 1;
                } while ( i0 < i1 );
            }
            // next segment
            icell = this.buf32[icell+1];
            if ( icell !== 0 && this.buf32[icell+2] === 0 ) {
                if ( ineedle === 0 || this.buf[ineedle-1] === 0x2E ) {
                    return ineedle;
                }
                icell = this.buf32[icell+1];
            }
        } while ( icell !== 0 );
        return ineedle === 0 || this.buf[ineedle-1] === 0x2E ? ineedle : -1;
    },
    matchesWASM: null,
    matches: null,

    create: function() {
        if ( this.buf32 === null ) {
            this.buf32 = new Uint32Array(this.buf.buffer);
        }
        const iroot = this.trie1 >>> 2;
        this.trie1 += 12;
        this.buf32[iroot+0] = 0;
        this.buf32[iroot+1] = 0;
        this.buf32[iroot+2] = 0;
        return new HNBigTrieRef(iroot);
    },

    add: function(iroot) {
        let ihnchar = this.buf[255];
        if ( ihnchar === 0 ) { return 0; }
        this.growBuf();
        let icell = iroot;
        // special case: first node in trie
        if ( this.buf32[icell+2] === 0 ) {
            this.buf32[icell+0] = 0;
            this.buf32[icell+1] = 0;
            this.buf32[icell+2] = this.addSegment(ihnchar);
            return 1;
        }
        // find a matching cell: move down
        for (;;) {
            const v = this.buf32[icell+2];
            // skip boundary cells
            if ( v === 0 ) {
                icell = this.buf32[icell+1];
                continue;
            }
            const imismatch = this.indexOfMismatch(v, ihnchar);
            let inext;
            // first character does not match: move to descendant
            if ( imismatch === 0 ) {
                // next descendant
                inext = this.buf32[icell+0];
                if ( inext !== 0 ) {
                    icell = inext;
                    continue;
                }
                this.buf32[icell+0] = this.addCell(0, 0, this.addSegment(ihnchar));
                return 1;
            }

            // first character(s) is(are) a match
            //
            // adjust characters left to process in hostname
            ihnchar -= imismatch;
            const lsegchar = v >>> 24;
            inext = this.buf32[icell+1];
            if ( imismatch === lsegchar ) {
                // needle remainder: yes
                if ( ihnchar !== 0 ) {
                    if ( inext !== 0 ) {
                        icell = inext;
                        continue;
                    }
                    // boundary cell + needle remainder
                    this.buf32[icell+1] = this.addCell(0, 0, 0);
                    this.buf32[this.buf32[icell+1]+1] = this.addCell(0, 0, this.addSegment(ihnchar));
                    return 1;
                }
                // needle remainder: no
                // boundary cell already present
                if ( inext === 0 || this.buf32[inext+2] === 0 ) { return 0; }
                // need boundary cell
                this.buf32[icell+1] = this.addCell(0, this.buf32[icell+1], 0);
                return 1;
            }

            // imismatch !== lsegchar
            // split current cell
            const isegchar = v & 0x00FFFFFF;
            this.buf32[icell+2] = (imismatch << 24) | isegchar;
            this.buf32[icell+1] = this.addCell(0, this.buf32[icell+1], (lsegchar - imismatch) << 24 | (isegchar + imismatch));
            // needle remainder: yes
            if ( ihnchar !== 0 ) {
                this.buf32[this.buf32[icell+1]+0] = this.addCell(0, 0, this.addSegment(ihnchar));
                return 1;
            }
            // needle remainder: no
            this.buf32[icell+1] = this.addCell(0, this.buf32[icell+1], 0);
            return 1;
        }
    },

    optimize: function() {
        this.segments = new Map();
        this.shrinkBuf();
    },

    fromIterable: function(hostnames) {
        const trieRef = this.create();
        for ( let hn of hostnames ) {
            this.setNeedle(hn).add(trieRef.iroot);
        }
        this.optimize();
        return trieRef;
    },

    addCell: function(idown, iright, v) {
        const icell = this.trie1 >>> 2;
        this.trie1 += 12;
        this.buf32[icell+0] = idown;
        this.buf32[icell+1] = iright;
        this.buf32[icell+2] = v;
        return icell;
    },

    addSegment: function(len) {
        if ( len === 0 ) { return 0; }
        const segment = this.needle.slice(0, len);
        let ichar = this.segments.get(segment);
        if ( ichar === undefined ) {
            ichar = this.char1 - this.char0;
            this.segments.set(segment, ichar);
            let i = len;
            while ( i-- ) {
                this.buf[this.char1++] = this.buf[i];
            }
        } else {
            this.savedByteCount += len;
        }
        return (len << 24) | ichar;
    },

    indexOfMismatch: function(v, ineedle) {
        let n = v >>> 24;
        if ( n > ineedle ) { n = ineedle; }
        const i0 = this.char0 + (v & 0x00FFFFFF);
        const i1 = i0 + n;
        let i = i0;
        let j = ineedle;
        while ( i < i1 ) {
            j -= 1;
            if ( this.buf[i] !== this.buf[j] ) { break; }
            i += 1;
        }
        return i - i0;
    },

    growBuf: function() {
        const char0 = (this.trie1 + 24 + 65535) & ~65535;
        const char1 = char0 + this.char1 - this.char0;
        const buf1 = (char1 + 256 + 65535) & ~65535;
        this.resizeBuf(char0, char1, buf1);
    },

    shrinkBuf: function() {
        const char0 = (this.trie1 + 3) & ~3;
        const char1 = char0 + this.char1 - this.char0;
        const buf1 = (char1 + 3) & ~3;
        this.resizeBuf(char0, char1, buf1);
    },

    resizeBuf: function(char0, char1, buf1) {
        if ( buf1 === this.buf.length ) { return; }
        const buf = new Uint8Array(buf1);
        buf.set(
            new Uint8Array(this.buf.buffer, 0, this.trie1),
            0
        );
        buf.set(
            new Uint8Array(this.buf.buffer, this.char0, this.char1 - this.char0),
            char0
        );
        this.char0 = char0;
        this.char1 = char1;
        this.buf = buf;
        if ( this.buf32 !== null ) {
            this.buf32 = new Uint32Array(this.buf.buffer);
        }
    },
};

/******************************************************************************/

(function() {
    // Default to javascript version.
    hnBigTrieManager.matches = hnBigTrieManager.matchesJS;

    if (
        typeof WebAssembly !== 'object' ||
        typeof WebAssembly.instantiateStreaming !== 'function'
    ) {
        return;
    }

    // Soft-dependency on vAPI so that the code here can be used outside of
    // uBO (i.e. tests, benchmarks)
    if (
        typeof vAPI === 'object' &&
        vAPI.webextFlavor.soup.has('firefox') === false
    ) {
        return;
    }

    // Soft-dependency on µBlock's advanced settings so that the code here can
    // be used outside of uBO (i.e. tests, benchmarks)
    if (
        typeof µBlock === 'object' &&
        µBlock.hiddenSettings.disableWebAssembly === true
    ) {
        return;
    }

    // The wasm module will work only if CPU is natively little-endian,
    // as we use native uint32 array in our trie-creation js code.
    const uint32s = new Uint32Array(1);
    const uint8s = new Uint8Array(uint32s.buffer);
    uint32s[0] = 1;
    if ( uint8s[0] !== 1 ) { return; }    

    // The directory from which the current script was fetched should also
    // contain the related WASM file. The script is fetched from a trusted
    // location, and consequently so will be the related WASM file.
    let workingDir;
    {
        const url = new URL(document.currentScript.src);
        const match = /[^\/]+$/.exec(url.pathname);
        if ( match !== null ) {
            url.pathname = url.pathname.slice(0, match.index);
        }
        workingDir = url.href;
    }

    const memory = new WebAssembly.Memory({ initial: 2 });

    hnBigTrieManager.wasmLoading = WebAssembly.instantiateStreaming(
        fetch(workingDir + 'wasm/hnbigtrie.wasm'),
        { imports: { memory } }
    ).then(result => {
        hnBigTrieManager.wasmLoading = null;
        if ( !result || !result.instance ) { return; }
        const pageCount = hnBigTrieManager.trie.byteLength >>> 16;
        if ( pageCount > 1 ) {
            memory.grow(pageCount - 1);
        }
        const buf = new Uint8Array(memory.buffer);
        buf.set(hnBigTrieManager.buf);
        hnBigTrieManager.buf = buf;
        if ( hnBigTrieManager.buf32 !== null ) {
            hnBigTrieManager.buf32 = new Uint32Array(buf.buffer);
        }
        hnBigTrieManager.wasmMemory = memory;
        hnBigTrieManager.matchesWASM = result.instance.exports.matches;
        hnBigTrieManager.matches = hnBigTrieManager.matchesWASM;
    }).catch(reason => {
        hnBigTrieManager.wasmLoading = null;
        console.error(reason);
    });
})();

/******************************************************************************/

const HNBigTrieRef = function(iroot) {
    this.id = hnBigTrieManager.id;
    this.iroot = iroot;
    this.size = 0;
};

HNBigTrieRef.prototype = {
    add: function(hn) {
        if ( hnBigTrieManager.setNeedle(hn).add(this.iroot) === 1 ) {
            this.size += 1;
            return true;
        }
        return false;
    },
    [Symbol.iterator]: function() {
        return {
            value: undefined,
            done: false,
            next: function() {
                if ( this.icell === 0 ) {
                    if ( this.forks.length === 0 ) {
                        this.value = undefined;
                        this.done = true;
                        return this;
                    }
                    const entry = this.forks.pop();
                    this.icell = entry.icell;
                    this.chars.length = entry.len;
                }
                for (;;) {
                    const idown = hnBigTrieManager.buf32[this.icell+0];
                    if ( idown !== 0 ) {
                        this.forks.push({
                            icell: idown,
                            len: this.chars.length
                        });
                    }
                    const v = hnBigTrieManager.buf32[this.icell+2];
                    let i0 = hnBigTrieManager.char0 + (v & 0x00FFFFFF);
                    const i1 = i0 + (v >>> 24);
                    while ( i0 < i1 ) {
                        this.chars.push(hnBigTrieManager.buf[i0]);
                        i0 += 1;
                    }
                    this.icell = hnBigTrieManager.buf32[this.icell+1];
                    if ( this.icell === 0 ) {
                        return this.toHostname();
                    }
                    if ( hnBigTrieManager.buf32[this.icell+2] === 0 ) {
                        this.icell = hnBigTrieManager.buf32[this.icell+1];
                        return this.toHostname();
                    }
                }
            },
            toHostname: function() {
                this.value = String.fromCharCode(...this.chars.slice().reverse());
                return this;
            },
            icell: this.iroot,
            chars: [],
            forks: [],
        };
    },
    isValid: function() {
        return this.id === hnBigTrieManager.id;
    },
    matches: function(needle) {
        return hnBigTrieManager.setNeedle(needle).matches(this.iroot);
    },
    matchesJS: function(needle) {
        return hnBigTrieManager.setNeedle(needle).matchesJS(this.iroot);
    },
    matchesWASM: function(needle) {
        return hnBigTrieManager.setNeedle(needle).matchesWASM(this.iroot);
    },
};
