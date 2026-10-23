// Exercise the production command builder with a minimal DOM; no native tool is run.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const options=JSON.parse(fs.readFileSync('master_app/cli_options.json','utf8'));
const fields=new Map();
const element=id=>{if(!fields.has(id))fields.set(id,{value:'',textContent:'',classList:{toggle(){}}});return fields.get(id);};
const context={escapeHTML:s=>s,document:{getElementById:element,querySelectorAll:()=>[]},console};
let source=fs.readFileSync('master_app/webscan.js','utf8');
source=source.replace('return {mount,unmount};',`return {mount,unmount,syncTarget,targetFromCommand,tokenize,configure(name,reference){tool=name;data={options:reference};config={target_kind:'file',target_option:'$input',utility:[]};previousTarget='';},setPrevious(value){previousTarget=value;}};`);
vm.createContext(context);vm.runInContext(source+'\nthis.builder=WebScanWorkspace;',context);
const builder=context.builder;
function tokens(){return Array.from(builder.tokenize(element('web-command').value));}
for(const tool of ['hashcat','john','aircrack-ng']){
  builder.configure(tool,options[tool]);
  element('web-command').value=tool+" '/tmp/old hashes.txt' /tmp/words.txt";
  builder.targetFromCommand();
  element('web-target').value='/tmp/new hashes.txt';builder.syncTarget();
  assert.deepEqual(tokens(),[tool,'/tmp/new hashes.txt','/tmp/words.txt'],tool+': replacing primary input must preserve candidate order');
  element('web-target').value='';builder.syncTarget();
  assert.deepEqual(tokens(),[tool,'/tmp/words.txt']);
  element('web-target').value='/tmp/third.txt';builder.syncTarget();
  assert.deepEqual(tokens(),[tool,'/tmp/third.txt','/tmp/words.txt'],tool+': typing a new primary input after clearing must retain candidates');
}
console.log('Workspace command-builder regression checks passed.');
