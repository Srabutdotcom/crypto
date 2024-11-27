import { hkdf, Uint16 } from "../dep.ts";
import { Struct, Constrained, sha256, sha384, sha512 } from "../dep.ts";


export function derivedSecret(secret, label, messages = new Uint8Array){
   const hashByteLength = secret.length;
   let hash = undefined
   switch (hashByteLength) {
      case 32: hash = sha256; break;
      case 48: hash = sha256; break;
      case 64: hash = sha512; break;
   }
   const context = hash
      .create()
      .update(Uint8Array.from(messages))
      .digest()
   return hkdfExpandLabel(secret, label, context, hashByteLength) 
}

export function hkdfExpandLabel(secret, label, context, hashByteLength){
   switch (hashByteLength) {
      case 32: return hkdf.expand(sha256, secret, Uint8Array.from(HkdfLabel.of(32, label, context)), 32)
      case 48: return hkdf.expand(sha384, secret, Uint8Array.from(HkdfLabel.of(48, label, context)), 48)
      case 64: return hkdf.expand(sha512, secret, Uint8Array.from(HkdfLabel.of(64, label, context)), 64)
   }
}

class HkdfLabel extends Struct {
   static of(hashByteLength, label, context){return new HkdfLabel(hashByteLength, label, context)}
   constructor(hashByteLength, label, context){
      super(
         Uint16.fromValue(hashByteLength),
         Label.of(label),
         Context.of(context)
      )
   }
}

class Label extends Constrained {
   static of(label){ return new Label(label)}
   constructor(label){
      super(7, 255, new TextEncoder().encode(`tls13 ${label}`))
   }
}

class Context extends Constrained {
   static of(context){ return new Context(context)}
   constructor(context){
      super(0, 255, context)
   }
}


//TODO: 
/* 
HKDF-Expand-Label(Secret, Label, Context, Length) =
HKDF-Expand(Secret, HkdfLabel, Length) 

Where HkdfLabel is specified as:

struct {
   uint16 length = Length;
   opaque label<7..255> = "tls13 " + Label;
   opaque context<0..255> = Context;
} HkdfLabel;

Derive-Secret(Secret, Label, Messages) =
   HKDF-Expand-Label(Secret, Label,
                     Transcript-Hash(Messages), Hash.length)
*/