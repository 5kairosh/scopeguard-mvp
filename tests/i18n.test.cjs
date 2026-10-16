const assert=require('node:assert/strict');
const I=require('../i18n.js');
globalThis.ScopeI18n=I;require('../features-i18n.js');
const M=require('../model.js');
const project=M.demo().projects[0],original=JSON.stringify(project),before=M.totals(project);
const keys=Object.keys(I.dictionaries.kk).sort();
for(const language of ['kk','ru','en']){
 assert.deepEqual(Object.keys(I.dictionaries[language]).sort(),keys,language+' dictionary is incomplete');
 I.setLanguage(language);
 assert.equal(I.getLanguage(),language);
 assert.match(I.t('eventApproved',{title:'API <test>',amount:'50 000 ₸',days:2}),/API <test>/);
 assert.equal(JSON.stringify(project),original);
 assert.deepEqual(M.totals(project),before);
}
I.setLanguage('ru');assert.equal(I.date('2026-11-03'),'3 ноя. 2026');
I.setLanguage('en');assert.equal(I.date('2026-11-03'),'3 Nov 2026');
I.setLanguage('kk');assert.equal(I.date('2026-11-03'),'3 қар. 2026');
console.log('PASS: complete dictionaries, interpolation, localized dates, unchanged project data and calculations.');

I.setLanguage('en');assert.equal(I.t('email'),'Username');
