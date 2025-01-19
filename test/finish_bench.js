import { finish_web, finish_noble, finish_stablelib } from "../src/finish/finish.js";

const f_key = Uint8Array.of(167, 115, 52, 163, 67, 114, 70, 189, 138, 107, 1, 118, 188, 96, 29, 85, 48, 179, 107, 104, 95, 120, 105, 111, 23, 20, 161, 145, 57, 51, 211, 153);
const data = Uint8Array.of(200, 214, 50, 159, 38, 23, 11, 29, 227, 93, 155, 38, 122, 243, 82, 169, 193, 120, 235, 241, 157, 241, 13, 5);


Deno.bench('Using Webcrypto', async ()=>{
   const finish = await finish_web(f_key, data);
})

Deno.bench('Using Noble', ()=>{
   const finish = finish_noble(f_key, data);
})

Deno.bench('Using Stablelib', ()=>{
   const finish = finish_stablelib(f_key, data);
})

/* 
benchmark         time/iter (avg)        iter/s      (min … max)           p75      p99     p995
----------------- ----------------------------- --------------------- --------------------------
Using Webcrypto          100.8 µs         9,922 ( 66.8 µs …   1.4 ms) 103.8 µs 148.0 µs 166.1 µs
Using Noble                8.8 µs       113,500 (  6.9 µs … 579.9 µs)   8.0 µs  45.6 µs  66.4 µs
Using Stablelib           11.3 µs        88,750 (  8.1 µs … 536.2 µs)   9.9 µs  61.8 µs  82.3 µs
 */