import net from "node:net"
const decoder = new TextDecoder();
const encoder = new TextEncoder();

export async function connect(option = { port: 587, hostname: "127.0.0.1", transport: "tcp" }) {
   const conn = await Deno.connect(option)
   return new DenoConnect(conn)
}

export async function nodeConnect(option = { port: 587, host: "127.0.0.1"}){
   return new Promise(resolve=>{
      const socket = net.connect(option, ()=>{
         console.log('connected')
         resolve(new NodeConnect(socket))  
      })
   })
}

class NodeConnect {
   #socket
   constructor(socket){
      this.#socket = socket;
   }
   async read(){
      return new Promise((resolve, reject) => {
         this.#socket.on("data", (data) => {
            //console.log(socket.data)
            resolve(data);
         });
         this.#socket.on("error", (error)=>{
            reject(error)
         })
         this.#socket.on("close", ()=>{
            reject(Error(`Connection closed`))
         })
      });
   }
   write(data){
      this.#socket.write(data)
   }
   async readString(){
      return decoder.decode(await this.read())
   }

   async writeString(string){
      this.write(string);
      return await this.readString()
   }

   async writeRead(byte){
      this.write(byte);
      return await this.read();
   }

   close(){
      return this.#socket.destroy();
   }

}

class DenoConnect {
   #conn

   constructor(conn) {
      this.#conn = conn;
   }
   async read() {
      const buffer = new Uint8Array(8192)
      const bytesRead = await this.#conn.read(buffer);
      return buffer.slice(0, bytesRead);
   }

   async readDecode() {
      const bufferRead = await this.read();
      return decoder.decode(bufferRead)
   }

   async write(byte) {
      return await this.#conn.write(byte)
   }

   async writeRead(byte){
      const bytesWritten = await this.write(byte);
      return await this.read();
   }

   async sendCommand(command) {
      const bytesWritten = await this.write(encoder.encode(command));
      return await this.readDecode()
   }

   get conn() {
      return this.#conn;
   }

   close() {
      this.#conn.close();
   }
}