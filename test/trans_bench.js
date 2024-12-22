import { Struct } from "../src/dep.ts"

class TranscriptMsg extends Set {
   //items = new Set
   byte
   constructor(...msgs){
      let arr = [];
      for(const msg of msgs ){
         if(!isUint8Array(msg))throw TypeError(`Expected Uint8Array`)
         //this.items.add(Array.from(msg));
         arr = arr.concat(Array.from(msg))
      }
      super([...msgs])
      this.byte = Uint8Array.from(arr)
   }
   insert(...msgs){
      for(const msg of msgs){
         if(!isUint8Array(msg))throw TypeError(`Expected Uint8Array`);
         this.add(msg);
         this.byte = Uint8Array.from(Array.from(this.byte).concat(Array.from(msg)))
      }
   }
}

function isUint8Array(data){
   return data instanceof Uint8Array
}

console.log(isUint8Array(Uint8Array.of(1,5,6)));

Deno.bench("Using Array", ()=>{
   const tm = new TranscriptMsg(Uint8Array.of(1,5,6), Uint8Array.of(11,51,16));
   const tmByte = tm.byte;
})

Deno.bench("Using Struct", ()=>{
   const tm = new Struct(Uint8Array.of(1,5,6), Uint8Array.of(11,51,16));
   const tmByte = tm.byte;
})

const test = new TranscriptMsg(Uint8Array.of(1,5,6), Uint8Array.of(11,51,16));
test.insert(Uint8Array.of(23,45,43), Uint8Array.of(22,42,41));
const [ a, b] = test

const _n = null;
debugger;