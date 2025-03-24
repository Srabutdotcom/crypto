export class Emitter extends EventTarget {
   emit(event, detail = null) {
      this.dispatchEvent(new CustomEvent(event, { detail }));
   }

   on(event, callback) {
      this.addEventListener(event, (e) => callback(e.detail));
   }

   off(event, callback) {
      this.removeEventListener(event, callback);
   }

   once(event, callback) {
      this.addEventListener(event, (e) => callback(e.detail), { once: true });
   }
}