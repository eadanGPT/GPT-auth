
export function installInventoryAPI(bot){
  return {
    list: ()=> bot.inventory.items().map(i=>({name:i.name,count:i.count,slot:i.slot})),
    equip: async (name)=>{
      const item = bot.inventory.items().find(i=>i.name===name);
      if (!item) throw new Error('Item not found');
      await bot.equip(item, 'hand');
    },
    drop: async (name)=>{
      const item = bot.inventory.items().find(i=>i.name===name);
      if (!item) throw new Error('Item not found');
      await bot.tossStack(item);
    }
  };
}
