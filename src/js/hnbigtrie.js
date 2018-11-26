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
/* exported HNBigTrie */

'use strict';

/*******************************************************************************

  HNBigTrieContainer is a flavor of trie modified from the original HNTrie
  code, found in ./hntrie.js -- which can also be used for reference.

  HNBigTrieContainer has the following features:

  - Designed to hold large number of hostnames
  - Hostnames can be added at any time (instead of all at once)
    - This means pre-sorting is not a requirement (unlike HNTrie)
  - The trie is always compact
    - This means there is no need for a `vacuum` method (unlike HNTrie)
  - It can return the exact hostname which caused the match

  It's primary purpose is to replace the use of Set() as a mean to hold
  large number of hostnames (ex. FilterHostnameDict in static filtering
  engine).

  A HNBigTrieContainer is mostly a large buffer in which distinct but related
  tries are stored. The memory layout of the buffer is as follow:

    0-254: needle being processed
      255: length of needle
  256-259: offset to start of trie data section (=> trie0)
  260-263: offset to end of trie data section (=> trie1)
  264-267: offset to start of character data section  (=> char0)
  268-271: offset to end of character data section (=> char1)
      272: start of trie data section

*/

const HNBigTrieContainer = function(details) {
    if ( details instanceof Object === false ) { details = {}; }
    this.buf = new Uint8Array(details.byteLength || 131072);
    this.buf32 = new Uint32Array(this.buf.buffer);
    this.needle = '';
    this.buf32[HNBIGTRIE_TRIE0_SLOT] = HNBIGTRIE_TRIE0_START;
    this.buf32[HNBIGTRIE_TRIE1_SLOT] = this.buf32[HNBIGTRIE_TRIE0_SLOT];
    this.buf32[HNBIGTRIE_CHAR0_SLOT] = details.char0 || 65536;
    this.buf32[HNBIGTRIE_CHAR1_SLOT] = this.buf32[HNBIGTRIE_CHAR0_SLOT];
    this.wasmInstancePromise = null;
    this.wasmMemory = null;
};

                                                                // i32 /  i8
const HNBIGTRIE_TRIE0_SLOT  = 256 >>> 2;                        //  64 / 256
const HNBIGTRIE_TRIE1_SLOT  = HNBIGTRIE_TRIE0_SLOT + 1;         //  65 / 260
const HNBIGTRIE_CHAR0_SLOT  = HNBIGTRIE_TRIE0_SLOT + 2;         //  66 / 264
const HNBIGTRIE_CHAR1_SLOT  = HNBIGTRIE_TRIE0_SLOT + 3;         //  67 / 268
const HNBIGTRIE_TRIE0_START = HNBIGTRIE_TRIE0_SLOT + 4 << 2;    //       272


HNBigTrieContainer.prototype = {

    //--------------------------------------------------------------------------
    // Public methods
    //--------------------------------------------------------------------------

    reset: function() {
        this.buf32[HNBIGTRIE_TRIE1_SLOT] = this.buf32[HNBIGTRIE_TRIE0_SLOT];
        this.buf32[HNBIGTRIE_CHAR1_SLOT] = this.buf32[HNBIGTRIE_CHAR0_SLOT];
    },

    readyToUse: function() {
        if ( HNBigTrieContainer.wasmModulePromise instanceof Promise === false ) {
            return Promise.resolve();
        }
        return HNBigTrieContainer.wasmModulePromise.then(module => {
            return this.initWASM(module);
        });
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
        const char0 = this.buf32[HNBIGTRIE_CHAR0_SLOT];
        let ineedle = this.buf[255];
        let icell = iroot;
        for (;;) {
            if ( ineedle === 0 ) { return -1; }
            ineedle -= 1;
            let c = this.buf[ineedle];
            let v, i0;
            // find first segment with a first-character match
            for (;;) {
                v = this.buf32[icell+2];
                i0 = char0 + (v & 0x00FFFFFF);
                if ( this.buf[i0] === c ) { break; }
                icell = this.buf32[icell+0];
                if ( icell === 0 ) { return -1; }
            }
            // all characters in segment must match
            let n = v >>> 24;
            if ( n > 1 ) {
                n -= 1;
                if ( n > ineedle ) { return -1; }
                i0 += 1;
                const i1 = i0 + n;
                do {
                    ineedle -= 1;
                    if ( this.buf[i0] !== this.buf[ineedle] ) { return -1; }
                    i0 += 1;
                } while ( i0 < i1 );
            }
            // next segment
            icell = this.buf32[icell+1];
            if ( icell === 0 ) { break; }
            if ( this.buf32[icell+2] === 0 ) {
                if ( ineedle === 0 || this.buf[ineedle-1] === 0x2E ) {
                    return ineedle;
                }
                icell = this.buf32[icell+1];
            }
        }
        return ineedle === 0 || this.buf[ineedle-1] === 0x2E ? ineedle : -1;
    },
    matchesWASM: null,
    matches: null,

    create: function() {
        const iroot = this.buf32[HNBIGTRIE_TRIE1_SLOT] >>> 2;
        this.buf32[HNBIGTRIE_TRIE1_SLOT] += 12;
        this.buf32[iroot+0] = 0;
        this.buf32[iroot+1] = 0;
        this.buf32[iroot+2] = 0;
        return new HNBigTrieRef(this, iroot);
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
        this.shrinkBuf();
        if (
            this.matchesWASM === null &&
            HNBigTrieContainer.wasmModulePromise !== null
        ) {
            HNBigTrieContainer.wasmModulePromise.then(module => {
                this.initWASM(module);
            });
        }
        return {
            byteLength: this.buf.byteLength,
            char0: this.buf32[HNBIGTRIE_CHAR0_SLOT],
        };
    },

    fromIterable: function(hostnames) {
        const trieRef = this.create();
        for ( let hn of hostnames ) {
            this.setNeedle(hn).add(trieRef.iroot);
        }
        return trieRef;
    },

    //--------------------------------------------------------------------------
    // Private methods
    //--------------------------------------------------------------------------

    addCell: function(idown, iright, v) {
        const icell = this.buf32[HNBIGTRIE_TRIE1_SLOT] >>> 2;
        this.buf32[HNBIGTRIE_TRIE1_SLOT] += 12;
        this.buf32[icell+0] = idown;
        this.buf32[icell+1] = iright;
        this.buf32[icell+2] = v;
        return icell;
    },

    addSegment: function(len) {
        if ( len === 0 ) { return 0; }
        let char1 = this.buf32[HNBIGTRIE_CHAR1_SLOT];
        const ichar = char1 - this.buf32[HNBIGTRIE_CHAR0_SLOT];
        let i = len;
        while ( i-- ) {
            this.buf[char1++] = this.buf[i];
        }
        this.buf32[HNBIGTRIE_CHAR1_SLOT] = char1;
        return (len << 24) | ichar;
    },

    indexOfMismatch: function(v, ineedle) {
        let n = v >>> 24;
        if ( n > ineedle ) { n = ineedle; }
        const i0 = this.buf32[HNBIGTRIE_CHAR0_SLOT] + (v & 0x00FFFFFF);
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
        if (
            (this.buf32[HNBIGTRIE_CHAR0_SLOT] - this.buf32[HNBIGTRIE_TRIE1_SLOT]) >= 24 &&
            (this.buf.length - this.buf32[HNBIGTRIE_CHAR1_SLOT]) >= 256
        ) {
            return;
        }
        const char0 = Math.max(
            (this.buf32[HNBIGTRIE_TRIE1_SLOT] + 24 + 65535) & ~65535,
            this.buf32[HNBIGTRIE_CHAR0_SLOT]
        );
        const char1 = Math.max(
            char0 + this.buf32[HNBIGTRIE_CHAR1_SLOT] - this.buf32[HNBIGTRIE_CHAR0_SLOT],
            this.buf32[HNBIGTRIE_CHAR1_SLOT]
        );
        const buf1 = Math.max(
            (char1 + 256 + 65535) & ~65535,
            this.buf.length
        );
        this.resizeBuf(char0, char1, buf1);
    },

    shrinkBuf: function() {
        if ( this.wasmMemory !== null ) { return; }
        const char0 = (this.buf32[HNBIGTRIE_TRIE1_SLOT] + 24 + 3) & ~3;
        const char1 = char0 + this.buf32[HNBIGTRIE_CHAR1_SLOT] - this.buf32[HNBIGTRIE_CHAR0_SLOT];
        const buf1 = (char1 + 256 + 3) & ~3;
        this.resizeBuf(char0, char1, buf1);
    },

    resizeBuf: function(char0, char1, buf1) {
        if ( buf1 === this.buf.length ) { return; }
        if ( this.wasmMemory !== null ) {
            const pageCount =  (buf1 + 65535 >>> 16) - (this.buf.byteLength + 65535 >>> 16);
            if ( pageCount > 0 ) {
                this.wasmMemory.grow(pageCount);
                this.buf = new Uint8Array(this.wasmMemory.buffer);
                this.buf32 = new Uint32Array(this.wasmMemory.buffer);
            }
            if ( char0 !== this.buf32[HNBIGTRIE_CHAR0_SLOT] ) {
                this.buf.set(
                    new Uint8Array(
                        this.wasmMemory.buffer,
                        this.buf32[HNBIGTRIE_CHAR0_SLOT],
                        this.buf32[HNBIGTRIE_CHAR1_SLOT] - this.buf32[HNBIGTRIE_CHAR0_SLOT]
                    ),
                    char0
                );
            }
        } else {
            const srcBuffer = this.buf.buffer;
            this.buf = new Uint8Array(buf1);
            this.buf.set(
                new Uint8Array(
                    srcBuffer,
                    0,
                    this.buf32[HNBIGTRIE_TRIE1_SLOT]
                ),
                0
            );
            this.buf.set(
                new Uint8Array(
                    srcBuffer,
                    this.buf32[HNBIGTRIE_CHAR0_SLOT],
                    this.buf32[HNBIGTRIE_CHAR1_SLOT] - this.buf32[HNBIGTRIE_CHAR0_SLOT]
                ),
                char0
            );
            this.buf32 = new Uint32Array(this.buf.buffer);
        }
        this.buf32[HNBIGTRIE_CHAR0_SLOT] = char0;
        this.buf32[HNBIGTRIE_CHAR1_SLOT] = char1;
    },

    initWASM: function(module) {
        if ( this.wasmInstancePromise === null ) {
            const memory = new WebAssembly.Memory({ initial: 1 });
            this.wasmInstancePromise = WebAssembly.instantiate(
                module,
                { imports: { memory } }
            );
            this.wasmInstancePromise.then(instance => {
                this.wasmMemory = memory;
                const pageCount = this.buf.byteLength + 65535 >>> 16;
                if ( pageCount > 1 ) {
                    memory.grow(pageCount - 1);
                }
                const buf = new Uint8Array(memory.buffer);
                buf.set(this.buf);
                this.buf = buf;
                this.buf32 = new Uint32Array(this.buf.buffer);
                this.matchesWASM = instance.exports.matches;
                this.matches = this.matchesWASM;
            });
        }
        return this.wasmInstancePromise;
    },
};

/******************************************************************************/

(function() {
    HNBigTrieContainer.wasmModulePromise = null;

    // Default to javascript version.
    HNBigTrieContainer.prototype.matches =
        HNBigTrieContainer.prototype.matchesJS;

    if (
        typeof WebAssembly !== 'object' ||
        typeof WebAssembly.compileStreaming !== 'function'
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
    // as we use native uint32 array in our js code.
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

    HNBigTrieContainer.wasmModulePromise = WebAssembly.compileStreaming(
        fetch(workingDir + 'wasm/hnbigtrie.wasm')
    ).catch(reason => {
        HNBigTrieContainer.wasmModulePromise = null;
        console.error(reason);
    });
})();

/******************************************************************************/

const HNBigTrieRef = function(container, iroot) {
    this.container = container;
    this.iroot = iroot;
    this.size = 0;
};

HNBigTrieRef.prototype = {
    add: function(hn) {
        if ( this.container.setNeedle(hn).add(this.iroot) === 1 ) {
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
                    this.charPtr = this.forks.pop();
                    this.icell = this.forks.pop();
                }
                for (;;) {
                    const idown = this.container.buf32[this.icell+0];
                    if ( idown !== 0 ) {
                        this.forks.push(idown, this.charPtr);
                    }
                    const v = this.container.buf32[this.icell+2];
                    let i0 = this.container.char0 + (v & 0x00FFFFFF);
                    const i1 = i0 + (v >>> 24);
                    while ( i0 < i1 ) {
                        this.charPtr -= 1;
                        this.charBuf[this.charPtr] = this.container.buf[i0];
                        i0 += 1;
                    }
                    this.icell = this.container.buf32[this.icell+1];
                    if ( this.icell === 0 ) {
                        return this.toHostname();
                    }
                    if ( this.container.buf32[this.icell+2] === 0 ) {
                        this.icell = this.container.buf32[this.icell+1];
                        return this.toHostname();
                    }
                }
            },
            toHostname: function() {
                this.value = this.textDecoder.decode(
                    new Uint8Array(this.charBuf.buffer, this.charPtr)
                );
                return this;
            },
            container: this.container,
            icell: this.iroot,
            charBuf: new Uint8Array(256),
            charPtr: 256,
            forks: [],
            textDecoder: new TextDecoder()
        };
    },
    matches: function(needle) {
        return this.container.setNeedle(needle).matches(this.iroot);
    },
    matchesJS: function(needle) {
        return this.container.setNeedle(needle).matchesJS(this.iroot);
    },
    matchesWASM: function(needle) {
        return this.container.setNeedle(needle).matchesWASM(this.iroot);
    },
};
