console.log("Hello via Bun!");
import { EventEmitter } from "events";
//import Emitter from "component-emitter"
import { Emitter } from "../event/event.js";


const emitter = new Emitter();

const eventObject = {
   data(socket: type, data) {
      //console.log(data.toString());
      this.data = data;
      emitter.emit("data");
   },
   open(socket) {
   },
   close(socket, error) {},
   drain(socket) {},
   error(socket, error) {},

   // client-specific handlers
   connectError(socket, error) {}, // connection failed
   end(socket) {}, // connection closed by server
   timeout(socket) {}, // connection timed out
   output: null,
};
debugger;
// The client
const socket = await Bun.connect({
   hostname: "smtp.gmail.com",
   port: 587,
   socket: eventObject,
});

async function getData() {
   return new Promise((resolve) => {
      emitter.on("data", () => {
         //console.log(socket.data)
         resolve(socket.data);
      });
   });
}

function writeRead(data) {
   socket.write(`EHLO mail.example.com\r\n`);
   //console.log(dataStore?.data.toString());
   let output = await getData();
   return output;
}

socket.write(`EHLO mail.example.com\r\n`);
//console.log(dataStore?.data.toString());
let output = await getData();
console.log("output " + output.toString());
output = await getData();
console.log("output " + output.toString());
debugger;
