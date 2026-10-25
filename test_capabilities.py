"""Optional metadata collector guards. Builtin APIs are never exercised as probes."""
import json
from pathlib import Path
import shutil
import subprocess
import unittest


@unittest.skipUnless(shutil.which('node'),'Node.js unavailable')
class CapabilityTests(unittest.TestCase):
    def test_builtin_metadata_without_sensitive_or_active_api_access(self):
        source=Path(__file__).with_name('tools').joinpath('collect-node-capabilities.cjs')
        # Run collector source in an isolated VM with an allowlisted builtin loader.
        # Throw on every sensitive property/active operation, rather than checking prose.
        harness=r'''
const vm=require('node:vm'),fs=require('node:fs');
const code=fs.readFileSync(process.argv[1],'utf8').replace(/^#!.*\n/,'');
const forbidden=()=>{throw Error('active/sensitive access forbidden');};
const noop=()=>{};
const modules={
 'node:http2':{connect:forbidden,createServer:forbidden},
 'node:tls':{connect:forbidden,createServer:forbidden},
 'node:dns':{lookup:forbidden,resolve:forbidden},
 'node:v8':{startupSnapshot:{isBuildingSnapshot:forbidden}},
 'node:sea':{isSea:()=>false},
 'node:zlib':{brotliDecompress:forbidden,brotliDecompressSync:forbidden,createBrotliDecompress:forbidden},
};
let output='';const calls=[];
const observed={versions:{node:'24.22.1',openssl:'3.5.0',PRIVATE:'SECRET'},platform:'synthetic',arch:'synthetic',features:{tls:true},permission:{has:forbidden},stdout:{write:value=>{output+=value;}},stderr:{write:forbidden}};
for(const key of ['env','argv','execArgv','execPath','config']) Object.defineProperty(observed,key,{get:forbidden});
vm.runInNewContext(code,{process:observed,require:name=>{calls.push(name);if(!(name in modules))throw Error('non-allowlisted import');return modules[name];}},{timeout:1000});
if(calls.some(name=>!(name in modules)))throw Error('unexpected import');
const data=JSON.parse(output);if(JSON.stringify(data).includes('SECRET'))throw Error('leaked');
if(data.capabilities.http2_api_available!==true||data.capabilities.sea_is_sea!==false)throw Error('metadata mismatch');
modules['node:sea']=null;modules['node:http2']=null;observed.permission=null;output='';
vm.runInNewContext(code,{process:observed,require:name=>modules[name]},{timeout:1000});
if(JSON.parse(output).capabilities.http2_api_available!==null)throw Error('absence must remain unknown');
console.log('guarded metadata verified');
'''
        result=subprocess.run([shutil.which('node'),'-e',harness,str(source)],capture_output=True,text=True,timeout=10)
        self.assertEqual(0,result.returncode,result.stderr)
        self.assertIn('guarded metadata verified',result.stdout)

    def test_real_local_builtin_report_shape_and_separate_legacy_contract(self):
        root=Path(__file__).parent
        result=subprocess.run([shutil.which('node'),str(root/'tools/collect-node-capabilities.cjs')],capture_output=True,text=True,check=True,timeout=10)
        data=json.loads(result.stdout)
        self.assertEqual('node-capabilities/1',data['schema_version'])
        self.assertEqual('unknown',data['application_use']);self.assertEqual('unknown',data['reachability'])
        self.assertEqual('not_tested',data['exploitability']);self.assertEqual('unknown',data['build_source'])
        self.assertEqual({'openssl','cares','brotli','v8'},set(data['library_versions']))
        self.assertTrue(all(type(value) is bool or value is None for value in data['capabilities'].values()))
        legacy=subprocess.run([shutil.which('node'),str(root/'collect-runtime.cjs')],capture_output=True,text=True,check=True,timeout=10)
        self.assertEqual(1,json.loads(legacy.stdout)['schema_version'])


if __name__=='__main__':unittest.main()
