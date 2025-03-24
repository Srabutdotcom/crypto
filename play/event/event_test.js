import { Emitter } from "./event.js";

const emitter = new Emitter;

emitter.emit('mulai')
emitter.on('mulai', ()=>{return "mulai"});

