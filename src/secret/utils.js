import { parseItems } from "../dep.ts";

export function parseData(array, dataType){
   const items = parseItems(array, 0, array.length, dataType)//new Set
   const output = new Map;
   for (const item of items) {
      output.set(item.type, item);
   }
   return output;
}