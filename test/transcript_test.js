import { TranscriptMsg } from "../src/secret/transcript.js";

const msg_0 = rnd(4);
const msg_1 = rnd(5);
const msg_2 = rnd(6);
const msg_3 = rnd(7);

const set = new Set([msg_0, msg_1]);
const values = [...set.values()];
function test(...val){
   const _n = val;
}

const test_0 = test(...set.values())

const transMsgs = new TranscriptMsg(msg_0, msg_1);
transMsgs.insert(msg_2, msg_3)

function rnd(n){
   return crypto.getRandomValues(new Uint8Array(n))
}


const _n = null;