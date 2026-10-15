import {spawnSync} from 'node:child_process';
function run(command,args){const r=spawnSync(command,args,{stdio:'inherit'});if(r.error)throw r.error;if(r.status!==0)process.exit(r.status||1);}
run(process.execPath,['node_modules/vite/bin/vite.js','build']);
run(process.platform==='win32'?'python':'python3',['scripts/package_project.py']);
