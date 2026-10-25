from pathlib import Path
import importlib.util
import json
import tempfile
import unittest
spec=importlib.util.spec_from_file_location('context',Path(__file__).parent/'tools/inspect-node-build-context.py')
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)


class BuildContextTests(unittest.TestCase):
    def test_engine_declarations_are_not_runtime_versions(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'metadata.json'
            for data in ({'engines':{'node':'>=22 <27'},'scripts':{'postinstall':'NEVER-EXECUTE'},'resolved':'https://SECRET.invalid'},
                         {'lockfileVersion':1,'dependencies':{'outer':{'engines':{'node':'>=22 <27'}}}},
                         {'lockfileVersion':2,'packages':{'node_modules/outer':{'engines':{'node':'>=22 <27'}}}},
                         {'lockfileVersion':3,'packages':{'node_modules/outer':{'engines':{'node':'>=22 <27'}}}}):
                path.write_text(json.dumps(data),encoding='utf-8');result=c.inspect(path)
                self.assertEqual('',result['runtime_version']);self.assertEqual('>=22 <27',result['observations'][0]['declared_node_range'])
                self.assertNotIn('SECRET',json.dumps(result));self.assertNotIn('NEVER-EXECUTE',json.dumps(result))
            path.write_text('{"engines":{"node":"https://SECRET.invalid"}}',encoding='utf-8')
            self.assertEqual('',c.inspect(path)['observations'][0]['declared_node_range'])

    def test_malformed_bounds_paths_and_absence(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'metadata.json'
            for text in ('{"engines":{},"engines":{}}','{"lockfileVersion":true}','{"lockfileVersion":3,"packages":{"../outside":{}}}','{"engines":[]}'):
                path.write_text(text,encoding='utf-8')
                with self.assertRaises(ValueError):c.inspect(path)
            path.write_text('{}',encoding='utf-8');self.assertEqual([],c.inspect(path)['observations'])
            path.write_bytes(b' '*(4*1024**2+1))
            with self.assertRaises(ValueError):c.inspect(path)


if __name__=='__main__':unittest.main()
