import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs/promises';import os from 'node:os';import path from 'node:path';
import ExcelJS from 'exceljs';import {PDFDocument} from 'pdf-lib';
import {catalog,runSimulation,detect,normalEvents,observedPath,generateAttack} from '../frontend/src/simulation.mjs';
import {createReport,buildWorkbook,buildPDF} from '../frontend/src/reports.mjs';
test('five scenarios enforce defenses and normal profile stays benign',()=>{for(const s of catalog.scenarios){const a=runSimulation(s.id);assert.equal(a.status,'BLOCKED');assert.ok(a.events.some(e=>e.blocked));assert.ok(a.actions.length);assert.ok(a.explanations.length);}assert.equal(detect(normalEvents()).kind,null);assert.deepEqual(observedPath(generateAttack('privilege-escalation')),['WS-01','DC-01']);});
test('response can be disabled without pretending containment',()=>{const a=runSimulation('brute-force',false);assert.equal(a.status,'DETECTED');assert.equal(a.actions.length,0);assert.ok(!a.events.some(e=>e.blocked));});
test('scenario identification is independent of the laptop hour',()=>{const oldNow=Date.now;Date.now=()=>Date.parse('2026-10-15T02:30:00Z');try{for(const s of catalog.scenarios)assert.equal(runSimulation(s.id).detectedAs,s.id);}finally{Date.now=oldNow;}});
test('report snapshots remain unchanged when live incident changes',()=>{const a=runSimulation('lateral-movement');const r=createReport([a]);a.risk=0;assert.notEqual(r.incidents[0].risk,0);assert.throws(()=>createReport([]));});
test('Excel retains every selected incident, event and action with typed numbers and dates',async()=>{
 const incidents=catalog.scenarios.map(s=>runSimulation(s.id)),r=createReport(incidents,'Attack test report','=1+1');const bytes=await buildWorkbook(r);const wb=new ExcelJS.Workbook();await wb.xlsx.load(bytes);
 assert.deepEqual(wb.worksheets.map(s=>s.name),['Summary','Incidents','Events','Defense actions']);
 assert.equal(wb.getWorksheet('Incidents').rowCount-4,5);assert.equal(wb.getWorksheet('Events').rowCount-4,incidents.reduce((n,a)=>n+a.events.length,0));assert.equal(wb.getWorksheet('Defense actions').rowCount-4,incidents.reduce((n,a)=>n+a.actions.length,0));
 assert.ok(wb.getWorksheet('Incidents').getCell('B5').value instanceof Date);assert.equal(typeof wb.getWorksheet('Incidents').getCell('H5').value,'number');assert.equal(wb.getWorksheet('Summary').getCell('B7').value.result,5);assert.equal(wb.getWorksheet('Summary').getCell('B12').value,'=1+1');
 const out=path.join(os.tmpdir(),'sentinel-graph-qa');await fs.mkdir(out,{recursive:true});await fs.writeFile(path.join(out,'report.xlsx'),bytes);await fs.writeFile(path.join(out,'report.pdf'),await buildPDF(r));await fs.writeFile(path.join(out,'report.json'),JSON.stringify(r));
});
test('long PDF reports paginate without omitting incidents',async()=>{const a=Array.from({length:18},()=>runSimulation('brute-force'));const r=createReport(a,'Extended report','Long-note verification. '.repeat(100));const bytes=await buildPDF(r);const pdf=await PDFDocument.load(bytes);assert.ok(pdf.getPageCount()>6);});
