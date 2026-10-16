const test=require('node:test'),assert=require('node:assert/strict'),M=require('../model.js');
test('revision history is immutable and only the selected proposal affects totals',()=>{
 const r={id:'r',status:'new'},p={budget:500000,deadline:'2026-11-01',requests:[r]};
 M.assessOptions(r,[{name:'Basic',hours:6,rate:5000,days:1},{name:'Standard',hours:14,rate:5000,days:3},{name:'Complete',hours:24,rate:5000,days:5}]);
 const first=structuredClone(r.estimateHistory[0]);assert.equal(M.totals(p).budget,500000);
 assert.throws(()=>M.decide(r,'approved'),/chooseOption/);
 M.requestRevision(r,'Please lower the standard estimate');assert.equal(r.status,'revision_requested');
 assert.throws(()=>M.decide(r,'approved',r.options[0].id));
 M.assessOptions(r,[{name:'Basic',hours:5,rate:5000,days:1},{name:'Standard',hours:10,rate:5000,days:2}]);
 assert.deepEqual(r.estimateHistory[0],first);assert.equal(r.estimateHistory.length,2);assert.equal(r.feedback[0].version,1);
 assert.throws(()=>M.decide(r,'approved',r.options[1].id,1),/staleVersion/);
 M.decide(r,'approved',r.options[1].id,2);assert.equal(M.totals(p).budget,550000);assert.equal(M.totals(p).deadline,'2026-11-03');
 assert.deepEqual(r.estimateHistory[0],first);assert.throws(()=>M.assessOptions(r,[{name:'New',hours:1,rate:1,days:1}]));
});
test('invalid and excessive options and blank revision feedback are rejected',()=>{
 assert.throws(()=>M.assessOptions({status:'new'},[]));
 assert.throws(()=>M.assessOptions({status:'new'},[{name:'x',hours:0,rate:5000,days:1}]));
 assert.throws(()=>M.assessOptions({status:'new'},[{name:' ',hours:1,rate:5000,days:1}]));
 assert.throws(()=>M.requestRevision({status:'assessed'},' '));
 const r={status:'assessed',hours:8,rate:5000,days:1,created:'2026-10-01'};
 M.assessOptions(r,[{name:'Updated',hours:10,rate:5000,days:2}]);
 assert.equal(r.estimateHistory.length,2);assert.equal(r.estimateHistory[0].options[0].hours,8);
});
