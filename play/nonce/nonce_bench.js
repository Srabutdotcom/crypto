import { ivXorSeq, ivXorSeqOptimized } from "./nonce.js";

const SEQ = 2 ** 53 + 2

const iv = Uint8Array.of(171, 26, 236, 38, 170, 120, 184, 252, 17, 118, 185, 172);
const nonce = ivXorSeq(iv, SEQ);
console.log(nonce.toString())

const nonce_1 = ivXorSeqOptimized(iv, SEQ);
console.log(nonce_1.toString())



Deno.bench("Using standard", () => {
   const nonce = ivXorSeq(iv, SEQ);
   //console.log(nonce.toString())
})

Deno.bench("Using Optimized", () => {
   const nonce_1 = ivXorSeqOptimized(iv, SEQ);
   //console.log(nonce_1.toString())
})

/* 
benchmark         time/iter (avg)        iter/s      (min … max)           p75      p99     p995
----------------- ----------------------------- --------------------- --------------------------
Using standard             2.1 µs       467,700 (  2.1 µs …   2.3 µs)   2.2 µs   2.3 µs   2.3 µs
Using Optimized            1.3 µs       780,700 (  1.2 µs …   1.5 µs)   1.3 µs   1.5 µs   1.5 µs
 */