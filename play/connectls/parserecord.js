import { Handshake, parseItems, TLSPlaintext } from "../../src/dep.ts";

export function parseRecords(array, type = "map") {
   if(type=="array")return parseItemsToArray(array, TLSPlaintext)
   return parseItemsToMap(array, TLSPlaintext)
}

export function parseHandshakes(array, type = "map") {
   if(type=="array")return parseItemsToArray(array, Handshake)
   return parseItemsToMap(array, Handshake)
}

function parseItemsToMap(array, dataType) {
   const items = parseItems(array, 0, array.length, dataType)//new Set
   const output = new Map;
   for (const item of items) {
      output.set(item.type, item);
   }
   return output;
}

function parseItemsToArray(array, dataType) {
   const items = parseItems(array, 0, array.length, dataType)//new Set
   const output = [];
   for (const item of items) {
      output.push(item);
   }
   return output;
}