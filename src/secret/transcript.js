import { safeuint8array } from "../dep.ts";

export class TranscriptMsg extends Set {
   //items = new Set
   constructor(...msgs) {
      super([...msgs])
   }
   insert(...msgs) {
      for (const msg of msgs) {
         this.add(msg);
      }
   }
   get byte(){
      return safeuint8array(...this.values())
   }
}
