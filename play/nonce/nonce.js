export function ivXorSeq(iv, seq) {
   const nonce = Uint8Array.from(iv);
   const buffer = new ArrayBuffer(8);
   const view = new DataView(buffer);
   const seqArr = new Uint8Array(buffer);
   view.setBigUint64(0, BigInt(seq));
   let i = 11;
   let j = 0n;
   let cons = BigInt(seq)
   while (true) {
      nonce[i] ^= seqArr[i - 4];
      cons -= BigInt(seqArr[i - 4]) * 256n ** j;
      if (cons == 0n) break;
      i -= 1; j += 1n
   }
   return nonce
}

export function ivXorSeqOptimized(iv, seq) {
   const nonce = Uint8Array.from(iv);
   const seqArr = new Uint8Array(8);
   const view = new DataView(seqArr.buffer);
   view.setBigUint64(0, BigInt(seq));

   let i = 11;
   let seqVal = seq;

   while (seqVal > 0) {
      nonce[i] ^= seqArr[i - 4];
      seqVal = Math.floor(seqVal / 256);
      i--;
   }
   return nonce;
}