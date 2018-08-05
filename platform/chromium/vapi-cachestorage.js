/*******************************************************************************

    uBlock Origin - a browser extension to block requests.
    Copyright (C) 2016-present The uBlock Origin authors

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

/* global IDBDatabase, WebAssembly, indexedDB */

'use strict';

/******************************************************************************/

// The code below has been originally manually imported from:
// Commit: https://github.com/nikrolls/uBlock-Edge/commit/d1538ea9bea89d507219d3219592382eee306134
// Commit date: 29 October 2016
// Commit author: https://github.com/nikrolls
// Commit message: "Implement cacheStorage using IndexedDB"

// The original imported code has been subsequently modified as it was not
// compatible with Firefox.
// (a Promise thing, see https://github.com/dfahlander/Dexie.js/issues/317)
// Furthermore, code to migrate from browser.storage.local to vAPI.cacheStorage
// has been added, for seamless migration of cache-related entries into
// indexedDB.

vAPI.cacheStorage = (function() {

    // Firefox-specific: we use indexedDB because chrome.storage.local() has
    // poor performance in Firefox. See:
    // https://bugzilla.mozilla.org/show_bug.cgi?id=1371255
    //if ( vAPI.webextFlavor.soup.has('firefox') === false ) {
    //    return vAPI.cacheStorage;
    //}

    const STORAGE_NAME = 'uBlock0CacheStorage';
    let db;
    let pendingInitialization;
    let textEncoder, textDecoder;

    let get = function get(input, callback) {
        if ( typeof callback !== 'function' ) { return; }
        if ( input === null ) {
            return getAllFromDb(callback);
        }
        var toRead, output = {};
        if ( typeof input === 'string' ) {
            toRead = [ input ];
        } else if ( Array.isArray(input) ) {
            toRead = input;
        } else /* if ( typeof input === 'object' ) */ {
            toRead = Object.keys(input);
            output = input;
        }
        return getFromDb(toRead, output, callback);
    };

    let set = function set(input, callback) {
        putToDb(input, callback);
    };

    let remove = function remove(key, callback) {
        deleteFromDb(key, callback);
    };

    let clear = function clear(callback) {
        clearDb(callback);
    };

    let getBytesInUse = function getBytesInUse(keys, callback) {
        // TODO: implement this
        callback(0);
    };

    let api = { get, set, remove, clear, getBytesInUse, error: undefined };

    let genericErrorHandler = function(ev) {
        let error = ev.target && ev.target.error;
        if ( error && error.name === 'QuotaExceededError' ) {
            api.error = error.name;
        }
        console.error('[%s]', STORAGE_NAME, error && error.name);
    };

    function noopfn() {
    }

    let lz4 = (function() {
        let lz4wasmInstance;
        let pendingInitialization;

        let init = function() {
            if ( lz4wasmInstance === null ) {
                return Promise.resolve(null);
            }
            if ( WebAssembly instanceof Object === false ) {
                lz4wasmInstance = null;
                return Promise.resolve(null);
            }
            if ( lz4wasmInstance instanceof WebAssembly.Instance ) {
                return Promise.resolve(lz4wasmInstance);
            }
            if ( pendingInitialization === undefined ) {
                pendingInitialization = WebAssembly.instantiateStreaming(
                    fetch('lib/lz4-block-codec.wasm', { mode: 'same-origin'})
                ).then(result => {
                    pendingInitialization = undefined;
                    lz4wasmInstance = result && result.instance || null;
                });
            }
            return pendingInitialization;
        };

        let growMemoryTo = function(byteLength) {
            let lz4api = lz4wasmInstance.exports;
            let neededByteLength = lz4api.getLinearMemoryOffset() + byteLength;
            let pageCountBefore = lz4api.memory.buffer.byteLength >>> 16;
            let pageCountAfter = (neededByteLength + 65535) >>> 16;
            if ( pageCountAfter > pageCountBefore ) {
                lz4api.memory.grow(pageCountAfter - pageCountBefore);
            }
            return lz4api.memory;
        };

        let encodeValue = function(key, value) {
            if ( value.length < 4096 ) { return value; }
            let t0 = window.performance.now();
            let lz4api = lz4wasmInstance.exports;
            let mem0 = lz4api.getLinearMemoryOffset();
            let memory = growMemoryTo(mem0 + 65536 * 4);
            let hashTable = new Int32Array(memory.buffer, mem0, 65536);
            hashTable.fill(-65536, 0, 65536);
            let hashTableSize = hashTable.byteLength;
            if ( textEncoder === undefined ) {
                textEncoder = new TextEncoder();
            }
            let inputArray = textEncoder.encode(value);
            let inputSize = inputArray.byteLength;
            let memSize =
                hashTableSize +
                inputSize +
                8 + lz4api.lz4BlockEncodeBound(inputSize);
            memory = growMemoryTo(memSize);
            let inputMem = new Uint8Array(
                memory.buffer,
                mem0 + hashTableSize,
                inputSize
            );
            inputMem.set(inputArray);
            let outputSize = lz4api.lz4BlockEncode(
                mem0 + hashTableSize,
                inputSize,
                mem0 + hashTableSize + inputSize + 8
            );
            if ( outputSize === 0 ) { return value; }
            let outputMem = new Uint8Array(
                memory.buffer,
                mem0 + hashTableSize + inputSize,
                8 + outputSize
            );
            outputMem[0] = 0x18;
            outputMem[1] = 0x4D;
            outputMem[2] = 0x22;
            outputMem[3] = 0x04;
            outputMem[4] = (inputSize >>>  0) & 0xFF;
            outputMem[5] = (inputSize >>>  8) & 0xFF;
            outputMem[6] = (inputSize >>> 16) & 0xFF;
            outputMem[7] = (inputSize >>> 24) & 0xFF;
            console.info(
                'uBO: [%s] compressed %d bytes into %d bytes in %s ms',
                key,
                inputSize,
                outputSize,
                (window.performance.now() - t0).toFixed(2)
            );
            return new Blob([ outputMem ]);
        };

        let resolveDecodedValue = function(resolve, ev, key, value) {
            let inputBuffer = ev.target.result;
            if ( inputBuffer instanceof ArrayBuffer === false ) {
                return resolve({ key, value });
            }
            let t0 = window.performance.now();
            let metadata = new Uint8Array(inputBuffer, 0, 8);
            if (
                metadata[0] !== 0x18 ||
                metadata[1] !== 0x4D ||
                metadata[2] !== 0x22 ||
                metadata[3] !== 0x04
            ) {
                return resolve({ key, value });
            }
            let inputSize = inputBuffer.byteLength - 8;
            let outputSize = 
                (metadata[4] <<  0) |
                (metadata[5] <<  8) |
                (metadata[6] << 16) |
                (metadata[7] << 24);
            let lz4api = lz4wasmInstance.exports;
            let mem0 = lz4api.getLinearMemoryOffset();
            let memSize = inputSize + outputSize;
            let memory = growMemoryTo(memSize);
            let inputArea = new Uint8Array(
                memory.buffer,
                mem0,
                inputSize
            );
            inputArea.set(new Uint8Array(inputBuffer, 8, inputSize));
            outputSize = lz4api.lz4BlockDecode(inputSize);
            if ( outputSize === 0 ) {
                return resolve({ key, value });
            }
            let outputArea = new Uint8Array(
                memory.buffer,
                mem0 + inputSize,
                outputSize
            );
            if ( textDecoder === undefined ) {
                textDecoder = new TextDecoder();
            }
            value = textDecoder.decode(outputArea);
            console.info(
                'uBO: [%s] decompressed %d bytes into %d bytes in %s ms',
                key,
                inputSize,
                outputSize,
                (window.performance.now() - t0).toFixed(2)
            );
            resolve({ key, value });
        };

        let decodeValue = function(key, value) {
            return new Promise(resolve => {
                let blobReader = new FileReader();
                blobReader.onloadend = ev => {
                    resolveDecodedValue(resolve, ev, key, value);
                };
                blobReader.readAsArrayBuffer(value);
            });
        };

        let encodeKeystore = function(keystore) {
            if ( lz4wasmInstance instanceof Object === false ) {
                return Promise.resolve(keystore);
            }
            return new Promise(resolve => {
                for ( let key in keystore ) {
                    if ( keystore.hasOwnProperty(key) === false ) { continue; }
                    let value = keystore[key];
                    if ( typeof value !== 'string' ) { continue; }
                    keystore[key] = encodeValue(key, value);
                }
                resolve(keystore);
            });
        };

        let decodeKeystore = function(keystore) {
            if ( lz4wasmInstance instanceof Object === false ) {
                return Promise.resolve(keystore);
            }
            let promises = [];
            let processResult = details => {
                keystore[details.key] = details.value;
            };
            for ( let key in keystore ) {
                if ( keystore.hasOwnProperty(key) === false ) { continue; }
                let value = keystore[key];
                if ( value instanceof Blob === false ) { continue; }
                promises.push(
                    decodeValue(key, value).then(processResult)
                );
            }
            return Promise.all(promises);
        };

        return {
            encode: function(keystore) {
                return init().then(( ) => {
                    return encodeKeystore(keystore);
                });
            },
            decode: function(keystore) {
                return init().then(( ) => {
                    return decodeKeystore(keystore);
                });
            }
        };
    })();

    let getDb = function getDb() {
        if ( db instanceof IDBDatabase ) {
            return Promise.resolve(db);
        }
        if ( db === null ) {
            return Promise.resolve(null);
        }
        if ( pendingInitialization !== undefined ) {
            return pendingInitialization;
        }
        // https://github.com/gorhill/uBlock/issues/3156
        //   I have observed that no event was fired in Tor Browser 7.0.7 +
        //   medium security level after the request to open the database was
        //   created. When this occurs, I have also observed that the `error`
        //   property was already set, so this means uBO can detect here whether
        //   the database can be opened successfully. A try-catch block is
        //   necessary when reading the `error` property because we are not
        //   allowed to read this propery outside of event handlers in newer
        //   implementation of IDBRequest (my understanding).
        pendingInitialization = new Promise(resolve => {
            let req;
            try {
                req = indexedDB.open(STORAGE_NAME, 1);
                if ( req.error ) {
                    console.log(req.error);
                    req = undefined;
                }
            } catch(ex) {
            }
            if ( req === undefined ) {
                pendingInitialization = undefined;
                db = null;
                resolve(null);
                return;
            }
            req.onupgradeneeded = function(ev) {
                req = undefined;
                let db = ev.target.result;
                db.onerror = db.onabort = genericErrorHandler;
                let table = db.createObjectStore(STORAGE_NAME, { keyPath: 'key' });
                table.createIndex('value', 'value', { unique: false });
            };
            req.onsuccess = function(ev) {
                pendingInitialization = undefined;
                req = undefined;
                db = ev.target.result;
                db.onerror = db.onabort = genericErrorHandler;
                resolve(db);
            };
            req.onerror = req.onblocked = function() {
                pendingInitialization = undefined;
                req = undefined;
                db = null;
                console.log(this.error);
                resolve(null);
            };
        });
        return pendingInitialization;
    };

    let getFromDb = function(keys, keystore, callback) {
        if ( typeof callback !== 'function' ) { return; }
        if ( keys.length === 0 ) { return callback(keystore); }
        let gotOne = function() {
            if ( typeof this.result === 'object' ) {
                keystore[this.result.key] = this.result.value;
            }
        };
        getDb().then(( ) => {
            if ( !db ) { return callback(); }
            let transaction = db.transaction(STORAGE_NAME);
            transaction.oncomplete =
            transaction.onerror =
            transaction.onabort = ( ) => {
                lz4.decode(keystore).then(( ) => {
                    callback(keystore);
                });
            };
            let table = transaction.objectStore(STORAGE_NAME);
            for ( let key of keys ) {
                let req = table.get(key);
                req.onsuccess = gotOne;
                req.onerror = noopfn;
                req = undefined;
            }
        });
    };

    let getAllFromDb = function(callback) {
        if ( typeof callback !== 'function' ) {
            callback = noopfn;
        }
        getDb().then(( ) => {
            if ( !db ) { return callback(); }
            let keystore = {};
            let transaction = db.transaction(STORAGE_NAME);
            transaction.oncomplete =
            transaction.onerror =
            transaction.onabort = ( ) => {
                lz4.decode(keystore).then(( ) => {
                    callback(keystore);
                });
            };
            callback();
            let table = transaction.objectStore(STORAGE_NAME),
                req = table.openCursor();
            req.onsuccess = function(ev) {
                let cursor = ev.target.result;
                if ( !cursor ) { return; }
                keystore[cursor.key] = cursor.value;
                cursor.continue();
            };
        });
    };

    // https://github.com/uBlockOrigin/uBlock-issues/issues/141
    //   Mind that IDBDatabase.transaction() and IDBObjectStore.put()
    //   can throw:
    //   https://developer.mozilla.org/en-US/docs/Web/API/IDBDatabase/transaction
    //   https://developer.mozilla.org/en-US/docs/Web/API/IDBObjectStore/put

    let putToDb = function(keystore, callback) {
        if ( typeof callback !== 'function' ) {
            callback = noopfn;
        }
        let keys = Object.keys(keystore);
        if ( keys.length === 0 ) { return callback(); }
        getDb().then(lz4.encode(keystore)).then(( ) => {
            if ( !db ) { return callback(); }
            let finish = ( ) => {
                if ( callback === undefined ) { return; }
                let cb = callback;
                callback = undefined;
                cb();
            };
            try {
                let transaction = db.transaction(STORAGE_NAME, 'readwrite');
                transaction.oncomplete =
                transaction.onerror =
                transaction.onabort = finish;
                let table = transaction.objectStore(STORAGE_NAME);
                for ( let key of keys ) {
                    let entry = {};
                    entry.key = key;
                    entry.value = keystore[key];
                    table.put(entry);
                    entry = undefined;
                }
            } catch (ex) {
                finish();
            }
        });
    };

    let deleteFromDb = function(input, callback) {
        if ( typeof callback !== 'function' ) {
            callback = noopfn;
        }
        let keys = Array.isArray(input) ? input.slice() : [ input ];
        if ( keys.length === 0 ) { return callback(); }
        getDb().then(db => {
            if ( !db ) { return callback(); }
            let finish = ( ) => {
                if ( callback === undefined ) { return; }
                let cb = callback;
                callback = undefined;
                cb();
            };
            try {
                let transaction = db.transaction(STORAGE_NAME, 'readwrite');
                transaction.oncomplete =
                transaction.onerror =
                transaction.onabort = finish;
                let table = transaction.objectStore(STORAGE_NAME);
                for ( let key of keys ) {
                    table.delete(key);
                }
            } catch (ex) {
                finish();
            }
        });
    };

    let clearDb = function(callback) {
        if ( typeof callback !== 'function' ) {
            callback = noopfn;
        }
        getDb().then(db => {
            if ( !db ) { return callback(); }
            let finish = ( ) => {
                if ( callback === undefined ) { return; }
                let cb = callback;
                callback = undefined;
                cb();
            };
            try {
                let req = db.transaction(STORAGE_NAME, 'readwrite')
                            .objectStore(STORAGE_NAME)
                            .clear();
                req.onsuccess = req.onerror = finish;
            } catch (ex) {
                finish();
            }
        });
    };

    // prime the db so that it's ready asap for next access.
    getDb(noopfn);

    return api;
}());

/******************************************************************************/
